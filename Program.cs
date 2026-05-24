using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        Console.WriteLine("=== SlothSec IP Reputation Checker ===");
        Console.Write("Enter an IP address: ");
        string ip = Console.ReadLine()!.Trim();

        if (!IsValidIP(ip))
        {
            Console.WriteLine("Invalid IP format.");
            return;
        }

        Console.WriteLine("Gathering intelligence....\n");

        var ipinfo = await GetIpInfo(ip);
        var ipapi = await GetIpApi(ip);
        var abuse = await CheckAbuseIPDB(ip);

        var score = CalculateRisk(ipinfo, ipapi, abuse);

        PrintReport(ip, ipinfo, ipapi, abuse, score);
        SaveReport(ip, ipinfo, ipapi, abuse, score);

        Console.WriteLine("\nDone. Report saved.");
    }

    static bool IsValidIP(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return false;

        return Regex.IsMatch(ip,
        @"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." +
        @"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." +
        @"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." +
        @"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$");   
    }

    class IpInfoResult
    {
        public string Ip { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string City { get; set; } = "";
        public string Region { get; set; } = "";
        public string Country { get; set; } = "";
        public string Org { get; set; } = "";
        public string Asn { get; set; } = "";
        public bool IsHosting { get; set; }
        public bool IsProxy { get; set; }
        public bool IsTor { get; set; }
        public bool Success { get; set; }
    }

    class IpApiResult
    {
        public string Status { get; set; } = "";
        public string Country { get; set; } = "";
        public string RegionName { get; set; } = "";
        public string City { get; set; } = "";
        public string Isp { get; set; } = "";
        public string Org { get; set; } = "";
        public string As { get; set; } = "";
        public bool Success => Status == "success";
    }

    class AbuseResult
    {
        public int Score { get; set; }
        public int TotalReports { get; set; }
        public string LastReported { get; set; } = "";
        public bool Success { get; set; }
    }

    class RiskScore
    {
        public int Value { get; set; }
        public string Level { get; set; } = "";
    }

    static async Task<IpInfoResult> GetIpInfo(string ip)
    {
        using var client = new HttpClient();
        string url = $"https://ipinfo.io/{ip}/json";

        try
        {
            var json = await client.GetStringAsync(url);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var result = new IpInfoResult
            {
                Success = true,
                Ip = root.GetPropertyOrDefault("ip"),
                Hostname = root.GetPropertyOrDefault("hostname"),
                City = root.GetPropertyOrDefault("city"),
                Region = root.GetPropertyOrDefault("region"),
                Country = root.GetPropertyOrDefault("country"),
                Org = root.GetPropertyOrDefault("org"),
                Asn = root.GetPropertyOrDefault("org")
            };
            
            if (root.TryGetProperty("privacy", out var privacy))
            {
                result.IsProxy = privacy.GetPropertyOrDefaultBool("proxy");
                result.IsTor = privacy.GetPropertyOrDefaultBool("tor");
                result.IsHosting = privacy.GetPropertyOrDefaultBool("hosting");
            }

            return result;
        }
        catch
        {
            return new IpInfoResult { Success = false };
        }
    }

    static async Task<IpApiResult> GetIpApi(string ip)
    {
        using var client = new HttpClient();
        string url = $"https://ipapi.co/{ip}/json/";

        try
        {
            var json = await client.GetStringAsync(url);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            bool error = root.TryGetProperty("error", out var errProp) && errProp.GetBoolean();

            return new IpApiResult
            {
                Status = error ? "fail" : "success",
                Country = root.GetPropertyOrDefault("country_name"),
                RegionName = root.GetPropertyOrDefault("region"),
                City = root.GetPropertyOrDefault("city"),
                Isp = root.GetPropertyOrDefault("org"),
                Org = root.GetPropertyOrDefault("org"),
                As = root.GetPropertyOrDefault("asn")
            };
        }
        catch
        {
            return new IpApiResult { Status = "fail" };
        }
    }

    static async Task<AbuseResult> CheckAbuseIPDB(string ip)
    {
        string apiKey = LoadAbuseKey();
        using var client = new HttpClient();

        client.DefaultRequestHeaders.Add("Key", apiKey);
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        string url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90";

        try
        {
            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"[AbuseIPDB ERROR] HTTP {response.StatusCode}");
                Console.WriteLine($"[AbuseIPDB BODY] {body}");
                return new AbuseResult { Success = false };
            }

            using var doc = JsonDocument.Parse(body);
            var data = doc.RootElement.GetProperty("data");

            return new AbuseResult
            {
                Success = true,
                Score = data.GetProperty("abuseConfidenceScore").GetInt32(),
                TotalReports = data.GetProperty("totalReports").GetInt32(),
                LastReported = data.GetProperty("lastReportedAt").GetString() ?? "Never"
            };

        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AbuseIPDB EXCEPTION] {ex.Message}");
            return new AbuseResult { Success = false };
        }
    }

    static string LoadAbuseKey()
    {
        return File.ReadAllText("abuseipdb.key").Trim();
    }
    static RiskScore CalculateRisk(IpInfoResult ipinfo, IpApiResult ipapi, AbuseResult abuse)
    {
        int score = 0;

        if (abuse.Success)
        {
            if (abuse.Score >= 80) score += 5;
            else if (abuse.Score >= 40) score += 3;
            else if (abuse.Score >= 0) score += 1;

            if (abuse.TotalReports >= 50) score += 3;
            else if (abuse.TotalReports >= 10) score += 2;
            else if (abuse.TotalReports > 0) score += 1;
        }

        if (ipinfo.Success)
        {
            if (ipinfo.IsTor) score += 5;
            if (ipinfo.IsProxy) score += 3;
            if (ipinfo.IsHosting) score += 3;
        }

        string org = (ipinfo.Org ?? "") + " " + (ipapi.Org ?? "");
        org = org.ToLower();

        if (org.Contains("hosting") || org.Contains("datacenter") || org.Contains("cloud"))
            score += 2;

        string country = (ipinfo.Country ?? ipapi.Country ?? "").ToUpper();
        if (country == "RU" || country == "CN" || country == "IR" || country == "KP")
            score += 2;

        string level =
            score >= 10 ? "High" :
            score >= 5 ? "Medium" :
            "Low";

        return new RiskScore { Value = score, Level = level };      
        }
                static void PrintReport(string ip, IpInfoResult ipinfo, IpApiResult ipapi, AbuseResult abuse, RiskScore risk)
    {
        Console.WriteLine("=== SlothSec IP Intelligence Report ===\n");
        Console.WriteLine($"IP: {ip}");
        Console.WriteLine($"Risk Level: {risk.Level} ({risk.Value})\n");

        Console.WriteLine("--- AbuseIPDB ---");
        if (abuse.Success)
        {
            Console.WriteLine($"Abuse Score: {abuse.Score}");
            Console.WriteLine($"Total Reports: {abuse.TotalReports}");
            Console.WriteLine($"Last Reported: {abuse.LastReported}");
        }
        else
        {
            Console.WriteLine("AbuseIPDB lookup failed.");
        }

        Console.WriteLine($"\n--- ipapi.co ---");
        if (ipapi.Success)
        {
            Console.WriteLine($"Location: {ipapi.City}, {ipapi.RegionName}, {ipapi.Country}");
            Console.WriteLine($"ISP: {ipapi.Isp}");
            Console.WriteLine($"Org: {ipapi.Org}");
            Console.WriteLine($"AS: {ipapi.As}");
        }
        else
        {
            Console.WriteLine("ipapi lookup failed.");
        }
    }

    static void SaveReport(string ip, IpInfoResult ipinfo, IpApiResult ipapi, AbuseResult abuse, RiskScore risk)
    {
        var report = new
        {
            IP = ip,
            CheckedAt = DateTime.UtcNow,
            Risk = risk,
            AbuseIPDB = abuse,
            IpInfo = ipinfo,
            IpApi = ipapi
        };

        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        string safeIp = ip.Replace(":", "_").Replace(".", "_");
        File.WriteAllText($"ipreport_{safeIp}.json", json);
    }
}
static class JsonExtensions
{
    public static string GetPropertyOrDefault(this JsonElement element, string name, string defaultValue = "")
    {
        return element.TryGetProperty(name, out var prop) && prop.ValueKind != JsonValueKind.Null
            ? prop.ToString()
            : defaultValue;
    }

    public static bool GetPropertyOrDefaultBool(this JsonElement element, string name, bool defaultValue = false)
    {
        if (element.TryGetProperty(name, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.True) return true;
            if (prop.ValueKind == JsonValueKind.False) return false;
        }
        return defaultValue;
    }


}
