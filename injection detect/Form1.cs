using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace injection_detect
{
    public partial class Form1 : Form
    {

        private DataTable dataTable;
        private Timer updateTimer;

        // Windows API constants and imports
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_READ = 0x0010;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const int MEM_COMMIT = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        public Form1()
        {
            InitializeComponent();

            InitializeDataTable();
            InitializeDataGridView();
            InitializeTimer();
        }

        private void InitializeDataTable()
        {
            dataTable = new DataTable();
            dataTable.Columns.Add("PID", typeof(int));
            dataTable.Columns.Add("Process Name", typeof(string));
            dataTable.Columns.Add("Memory Region", typeof(string));
            dataTable.Columns.Add("Size", typeof(string));
            dataTable.Columns.Add("Architecture", typeof(string)); 
        }

            private void InitializeDataGridView()
        {
            dataGridView1.DataSource = dataTable;
            dataGridView1.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        }
        private void Log(string message)
        {
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string logFilePath = Path.Combine(desktopPath, "injection.logs");

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logEntry = $"{timestamp}: {message}\n";

            File.AppendAllText(logFilePath, logEntry);
        }
        private void InitializeTimer()
        {
            updateTimer = new Timer();
            updateTimer.Interval = 5000; // Update every 1 seconds
            updateTimer.Tick += UpdateTimer_Tick;
            updateTimer.Start();
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            UpdateProcessInfo();
        }

        private void UpdateProcessInfo()
        {
            dataTable.Rows.Clear();
            int currentPid = Process.GetCurrentProcess().Id;

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id != currentPid && process.ProcessName.ToLower() != "cmd.exe")
                    {
                        string architecture = IsProcess64Bit(process) ? "x64" : "x32";
                        CheckMemoryRegions(process.Id, process.ProcessName, architecture);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception || ex is NotSupportedException)
                {
                    // Handle exceptions related to accessing process information
                }
            }
        }

        private bool IsProcess64Bit(Process process)
        {
            try
            {
                bool is64BitProcess = (process.MainModule.ModuleMemorySize > Int32.MaxValue);
                return is64BitProcess;
            }
            catch
            {
                // The process might not have access to MainModule, default to false.
                return false;
            }
        }

        private void CheckMemoryRegions(int pid, string processName, string architecture)
        {
            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

            if (processHandle != IntPtr.Zero)
            {
                MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
                IntPtr baseAddress = IntPtr.Zero;

                while (VirtualQueryEx(processHandle, baseAddress, out memInfo, (uint)Marshal.SizeOf(memInfo)) != 0)
                {
                    if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_EXECUTE_READWRITE)
                    {
                        string logMessage = $"PID: {pid}, Process Name: {processName}, Suspicious RWX Memory Region: {memInfo.BaseAddress}, Size: {memInfo.RegionSize}";
                        dataTable.Rows.Add(pid, processName, memInfo.BaseAddress.ToString(), memInfo.RegionSize.ToString(), architecture);
                        Log(logMessage); // Logging the information
                    }
                    long newAddress = (long)baseAddress + (long)memInfo.RegionSize;
                    // Safely increment baseAddress
                    if (Environment.Is64BitProcess)
                    {
                        if (newAddress > Int64.MaxValue)
                        {
                            break;
                        }
                    }
                    else
                    {
                        if (newAddress > Int32.MaxValue)
                        {
                            break;
                        }
                    }
                    baseAddress = new IntPtr(newAddress);
                }

                CloseHandle(processHandle);
            }
        }




    }
}
