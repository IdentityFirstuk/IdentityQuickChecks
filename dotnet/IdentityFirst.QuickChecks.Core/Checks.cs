using System;
using System.Collections.Generic;
using System.Text.Json;

namespace IdentityFirst.QuickChecks.Core
{
    // Small prototype library exposing a sample check to be called from PowerShell.
    public static class Checks
    {
        public static string RunSampleCheck()
        {
            var result = new Dictionary<string, object>
            {
                ["Name"] = "SampleCheck",
                ["Timestamp"] = DateTime.UtcNow.ToString("o"),
                ["Status"] = "OK",
                ["Details"] = new Dictionary<string, object>
                {
                    ["Message"] = "This is a native prototype result from IdentityFirst.QuickChecks.Core",
                    ["Value"] = 42
                }
            };

            return JsonSerializer.Serialize(result);
        }
    }
}
