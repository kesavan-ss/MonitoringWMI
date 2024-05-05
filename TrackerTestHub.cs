using System;
using System.Management;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using Microsoft.Win32;

class Program
{
    static void Main()
    {
        //T1 working
        // Subscribe to the NetworkAvailabilityChanged event
        //NetworkChange.NetworkAvailabilityChanged += NetworkAvailabilityChangedHandler;

        ////Console.WriteLine("Press Enter to exit.");
        ////Console.ReadLine();

        //DisplayNetworkInterfaceInformation();

        ////T2
        //// Set up a timer to periodically check for changes
        Timer timer = new Timer(EventCheckNow, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

        Console.WriteLine("Press Enter to exit.");
        Console.ReadLine();

        // Dispose the timer when done
        timer.Dispose();

        ////T3
        //ApplicationUsage();//T3 Working
        //NetworkTracker(); //T4 Need to test
        ////T5
        //MonitorSystemResourceUsage();//WOrking
        ////T6
        //MonitorSystemResourceUsageMain();//Working
        ////T7
        //processErrorReading();//Partial Working
        ////T8
        //GetInstalledAllApplications();//WOrking
        ////T9
        //GetInstalledUserApplications();//Working v1
        ////T10
        ////GetInstalledUserApplicationsMain();
        ////T11
        //ReadEventLog("Application"); //Working
        //T12
        //ReadChromeEvent(); //Working
    }

    static void ReadEventLog(string eventLogName)
    {
        try
        {
            // Open the specified event log
            EventLog eventLog = new EventLog(eventLogName);

            // Display information about the event log
            Console.WriteLine($"Reading from event log: {eventLog.LogDisplayName}");
            Console.WriteLine($"Total number of entries: {eventLog.Entries.Count}");

            // Iterate over the entries in the event log and display them
            foreach (EventLogEntry entry in eventLog.Entries)
            {
                Console.WriteLine($"Entry Type: {entry.EntryType}");
                Console.WriteLine($"Event ID: {entry.InstanceId}");
                Console.WriteLine($"Message: {entry.Message}");
                Console.WriteLine($"Time Generated: {entry.TimeGenerated}");
                Console.WriteLine();
            }

            // Close the event log
            eventLog.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    static void GetInstalledUserApplications()
    {
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product WHERE InstallLocation IS NOT NULL");
            ManagementObjectCollection products = searcher.Get();

            foreach (ManagementObject product in products)
            {
                string name = product["Name"] as string;
                string version = product["Version"] as string;
                string vendor = product["Vendor"] as string;
                string installLocation = product["InstallLocation"] as string;

                Console.WriteLine($"Name: {name}, Version: {version}, Vendor: {vendor}, InstallLocation: {installLocation}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    static void GetInstalledAllApplications()
    {
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product");
            ManagementObjectCollection products = searcher.Get();

            foreach (ManagementObject product in products)
            {
                string name = product["Name"] as string;
                string version = product["Version"] as string;
                string vendor = product["Vendor"] as string;

                Console.WriteLine($"Name: {name}, Version: {version}, Vendor: {vendor}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    static void processErrorReading()
    {
        Process process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "C:\\Program Files\\Adobe\\Adobe Photoshop 2023\\Photoshop.exe", // Assuming chrome.exe is in the system's PATH
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.ErrorDataReceived += (sender, e) =>
        {
            if (e.Data != null)
            {
                Console.WriteLine($"Error output: {e.Data}");
            }
        };

        process.Start();

        // Begin asynchronous reading of error output
        process.BeginErrorReadLine();

        // Other code or tasks can run concurrently here...

        // Wait for the process to exit and clean up
        process.WaitForExit();
        process.Close();
    }
    static void MonitorSystemResourceUsage()
    {
        PerformanceCounter cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
        PerformanceCounter ramCounter = new PerformanceCounter("Memory", "Available MBytes");
        PerformanceCounter diskCounter = new PerformanceCounter("LogicalDisk", "% Free Space", "C:");

        while (true)
        {
            // Retrieve and display CPU usage
            float cpuUsage = cpuCounter.NextValue();
            Console.WriteLine($"CPU Usage: {cpuUsage}%");

            // Retrieve and display available RAM
            float availableRAM = ramCounter.NextValue();
            Console.WriteLine($"Available RAM: {availableRAM} MB");

            // Retrieve and display % free space on C: drive
            float freeDiskSpace = diskCounter.NextValue();
            Console.WriteLine($"Free Disk Space (C:): {freeDiskSpace}%");

            Console.WriteLine("------------------------------");

            // Sleep for a short interval before checking again
            System.Threading.Thread.Sleep(1000); // Adjust as needed
        }
    }
    static void MonitorSystemResourceUsageMain()
    {
        PerformanceCounter ramCounter = new PerformanceCounter("Memory", "Available MBytes");

        while (true)
        {
            // Retrieve and display available RAM
            float availableRAM = ramCounter.NextValue();
            Console.WriteLine($"Available RAM: {availableRAM} MB");

            // Display detailed process memory usage
            DisplayProcessMemoryUsage();

            Console.WriteLine("------------------------------");

            // Sleep for a short interval before checking again
            System.Threading.Thread.Sleep(1000); // Adjust as needed
        }
    }
    static void DisplayProcessMemoryUsage()
    {
        Console.WriteLine("Process Memory Usage:");

        Process[] processes = Process.GetProcesses();
        foreach (Process process in processes)
        {
            try
            {
                Console.WriteLine($"{process.ProcessName}: {process.WorkingSet64 / (1024 * 1024)} MB");
            }
            catch (Exception ex)
            {
                // Handle exceptions (e.g., access denied to some processes)
                Console.WriteLine($"{process.ProcessName}: Error - {ex.Message}");
            }
        }
    }
    static void NetworkTracker()
    {
        // List available network devices
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1)
        {
            Console.WriteLine("No network devices found.");
            return;
        }

        Console.WriteLine("Available network devices:");
        for (int i = 0; i < devices.Count; i++)
        {
            Console.WriteLine($"{i + 1}. {devices[i].Description}");
        }

        Console.Write("Select a device (enter the number): ");
        int selectedDeviceIndex;
        if (int.TryParse(Console.ReadLine(), out selectedDeviceIndex) && selectedDeviceIndex >= 1 && selectedDeviceIndex <= devices.Count)
        {
            // Open the selected device for capturing
            ICaptureDevice device = devices[selectedDeviceIndex - 1];
            device.OnPacketArrival += Device_OnPacketArrival;
            device.Open(DeviceMode.Promiscuous, 1000); // Open in promiscuous mode with a 1-second timeout
            device.StartCapture();

            Console.WriteLine($"Capturing network traffic on {device.Description}. Press Enter to stop.");
            Console.ReadLine();

            // Stop capturing and close the device when done
            device.StopCapture();
            device.Close();
        }
        else
        {
            Console.WriteLine("Invalid selection.");
        }
    }

    private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
        // Process captured packet
        var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
        Console.WriteLine($"Captured packet: {packet}");
    }
    static void ApplicationUsage()
    {
        foreach (var process in Process.GetProcesses())
            {
                Console.WriteLine($"Process Name: {process.ProcessName}, ID: {process.Id}");

                // Log or store process information
            }
        
    }
    static void EventCheckNow(object state)
    {
        //ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
        //foreach (ManagementObject process in searcher.Get())
        //{
        //    Console.WriteLine($"Process Name: {process["Name"]}");
        //    Console.WriteLine($"Process ID: {process["ProcessId"]}");
        //}
        EventQuery query = new EventQuery();
        query.QueryString = "SELECT * FROM" +
            " __InstanceCreationEvent WITHIN 1 " +
            "WHERE TargetInstance isa \"Win32_Process\"";

        // Initialize an event watcher and subscribe to events
        // that match this query
        ManagementEventWatcher watcher =
            new ManagementEventWatcher(query);
        // times out watcher.WaitForNextEvent in 5 seconds
        watcher.Options.Timeout = new TimeSpan(0, 0, 5);

        // Block until the next event occurs
        // Note: this can be done in a loop if waiting for
        // more than one occurrence
        Console.WriteLine(
            "Open an application (notepad.exe) to trigger an event.");
        ManagementBaseObject e = watcher.WaitForNextEvent();

        //Display information from the event
        Console.WriteLine(
            "Process {0} has been created, path is: {1}",
            ((ManagementBaseObject)e
            ["TargetInstance"])["Name"],
            ((ManagementBaseObject)e
            ["TargetInstance"])["ExecutablePath"]);

        //Cancel the subscription
        watcher.Stop();

    }
    static void DisplayNetworkInterfaceInformation()
    {
        Console.WriteLine("Current Network Interfaces:");

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"Interface: {nic.Description}");
            Console.WriteLine($"   Status: {nic.OperationalStatus}");
            Console.WriteLine($"   Speed: {nic.Speed} bps");
            Console.WriteLine($"   Bytes Sent: {nic.GetIPv4Statistics().BytesSent}");
            Console.WriteLine($"   Bytes Received: {nic.GetIPv4Statistics().BytesReceived}");
            Console.WriteLine("----------------------------");
        }
    }

    static void CheckForNetworkChanges(object state)
    {
        Console.WriteLine("Checking for network changes...");

        // Display updated network interface information
        DisplayNetworkInterfaceInformation();
    }
    static void NetworkAvailabilityChangedHandler(object sender, NetworkAvailabilityEventArgs e)
    {
        if (e.IsAvailable)
        {
            Console.WriteLine("Network connection is available.");
        }
        else
        {
            Console.WriteLine("Network connection is unavailable.");
        }
    }
    static void ReadChromeEvent()
    {
        string chromeSource = "Chrome_Process";
        ReadApplicationEvents(chromeSource);
    }
    static void ReadApplicationEvents(string applicationName)
    {
        try
        {
            // Open the "Application" event log
            EventLog eventLog = new EventLog("Application");

            // Display information about the event log
            Console.WriteLine($"Reading events from the 'Application' log...");

            // Iterate over the entries in the event log and filter by application name
            foreach (EventLogEntry entry in eventLog.Entries)
            {
                if (entry.Source.Equals(applicationName, StringComparison.OrdinalIgnoreCase))
                {
                    // Display information about the event
                    Console.WriteLine($"Event Type: {entry.EntryType}");
                    Console.WriteLine($"Event ID: {entry.InstanceId}");
                    Console.WriteLine($"Source: {entry.Source}");
                    Console.WriteLine($"Message: {entry.Message}");
                    Console.WriteLine($"Time Generated: {entry.TimeGenerated}");
                    Console.WriteLine();
                }
            }

            // Close the event log
            //eventLog.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
