// ============================================================================
//  LolBypass.cs
//  Восстановление доступа к серверам League of Legends / Riot Games (РФ):
//  проверка каждого домена реестра (TCP 443 + TLS handshake с SNI) и, если
//  домен мёртв напрямую, пининг на живой IP из резервных диапазонов
//  Cloudflare (108.162.192.0/18, 190.93.240.0/20, 198.41.128.0/17) в файл
//  %SystemRoot%\System32\drivers\etc\hosts.
//
//  Сборка: build.bat (csc.exe из .NET Framework v4.0.30319).
//  Язык: C# 5.0 — без синтаксиса C#6+ (без $"", ?., nameof и т.п.).
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LolBypass
{
    /// <summary>Запись реестра хостов.</summary>
    public class HostEntry
    {
        public string Host;
        public bool Critical;

        public HostEntry(string host, bool critical)
        {
            Host = host;
            Critical = critical;
        }
    }

    /// <summary>Результат проверки одного хоста.</summary>
    public class HostResult
    {
        public HostEntry Entry;
        public string PinnedIp = "";            // старый пин, найденный в hosts
        public List<IPAddress> ResolvedV4 = new List<IPAddress>();
        public bool DirectOk;
        public long DirectMs = -1;
        public string DirectError = "";
        public string BestIp = "";              // лучший обходной IP из пула CF
        public long BestAvgMs = -1;
        public int BypassAliveCount;
        public int ActionKind;                  // 0 оставлено, 1 pin, 2 removed, 3 fail
        public string Action = "FAIL-нет_обхода";
        public string NewPinIp = "";
    }

    /// <summary>Результат диагностики чат-сервера (порт 5223).</summary>
    public class ChatResult
    {
        public string Host;
        public bool Ok;
        public long Ms = -1;
        public string Error = "";
    }

    public static class Program
    {
        private const string BlockStart = "# >>> lol-bypass manage >>>";
        private const string BlockEnd = "# <<< lol-bypass <<<";
        private const int ConnectTimeoutMs = 4000;
        private const int TlsTimeoutMs = 4000;

        // ------------------------- Реестр хостов -------------------------------
        private static readonly HostEntry[] HostRegistry = new HostEntry[]
        {
            // Критичные (вход/логин/клиент)
            new HostEntry("clientconfig.rpg.riotgames.com", true),
            new HostEntry("authenticate.riotgames.com", true),
            new HostEntry("auth.riotgames.com", true),
            new HostEntry("account.riotgames.com", true),
            new HostEntry("entitlements.auth.riotgames.com", true),
            new HostEntry("data.riotgames.com", true),
            new HostEntry("riot-geo.pas.si.riotgames.com", true),
            new HostEntry("riot-geo.mps.si.riotgames.com", true),
            new HostEntry("content.publishing.riotgames.com", true),
            new HostEntry("eu.edge.rms.si.riotgames.com", true),
            new HostEntry("login.leagueoflegends.com", true),
            // Дополнительные (клиент игры, сайты, статистика) — сбой не критичен
            new HostEntry("lol.secure.dyn.riotcdn.net", false),
            new HostEntry("lol.dyn.riotcdn.net", false),
            new HostEntry("teamfighttactics.secure.dyn.riotcdn.net", false),
            new HostEntry("riot-client.secure.dyn.riotcdn.net", false),
            new HostEntry("riot-client.dyn.riotcdn.net", false),
            new HostEntry("ks-foundation.secure.dyn.riotcdn.net", false),
            new HostEntry("bacon.secure.dyn.riotcdn.net", false),
            new HostEntry("ritoplus.secure.dyn.riotcdn.net", false),
            new HostEntry("www.leagueoflegends.com", false),
            new HostEntry("ddragon.leagueoflegends.com", false),
            new HostEntry("status.riotgames.com", false),
            new HostEntry("support.riotgames.com", false),
            new HostEntry("signup.id.riotgames.com", false),
            new HostEntry("porofessor.gg", false),
            new HostEntry("leagueofgraphs.com", false)
        };

        // ------------------- Пул резервных IP Cloudflare -----------------------
        private static readonly string[] CfBackupPool = new string[]
        {
            "108.162.192.96", "108.162.192.100", "108.162.192.101", "108.162.192.102", "108.162.192.103",
            "108.162.192.104", "108.162.192.110", "108.162.192.115", "108.162.192.120", "108.162.192.125",
            "190.93.240.96", "190.93.241.96", "190.93.242.96", "190.93.243.96", "190.93.244.96",
            "190.93.245.96", "190.93.246.96", "190.93.246.100", "190.93.247.96", "190.93.247.100",
            "198.41.128.96", "198.41.160.96", "198.41.176.96", "198.41.192.96", "198.41.192.100",
            "198.41.200.96", "198.41.224.96", "198.41.240.96"
        };

        // Диагностика чата (не чинится через hosts)
        private static readonly string[] ChatHosts = new string[]
        {
            "eun1.chat.si.riotgames.com",
            "euw1.chat.si.riotgames.com"
        };

        private static readonly object LogSync = new object();
        private static string LogPath = "";
        private static bool ScanMode;

        private static int Main(string[] args)
        {
            LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "lolbypass.log");
            try { Console.OutputEncoding = Encoding.UTF8; }
            catch (Exception ex) { LogFileOnly("WARN: не удалось установить UTF-8 для консоли: " + ex.Message); }
            try { ThreadPool.SetMinThreads(1024, 1024); }
            catch (Exception ex) { LogFileOnly("WARN: SetMinThreads: " + ex.Message); }

            ScanMode = false;
            if (args != null)
            {
                foreach (string a in args)
                {
                    if (string.Equals(a, "-scan", StringComparison.OrdinalIgnoreCase))
                    {
                        ScanMode = true;
                    }
                }
            }

            try
            {
                return Run();
            }
            catch (Exception ex)
            {
                LogFileOnly("ФАТАЛЬНО: " + ex.ToString());
                try { Console.WriteLine("ФАТАЛЬНАЯ ОШИБКА: " + ex.Message); }
                catch (Exception ex2) { LogFileOnly("console write failed: " + ex2.Message); }
                WaitAtEnd();
                return 1;
            }
        }

        // ===================================================================
        //  Основной сценарий
        // ===================================================================
        private static int Run()
        {
            Log("");
            Log("=====================================================================");
            Log(" LolBypass — проверка/восстановление доступа к серверам Riot Games");
            Log(string.Format(" Запуск: {0:yyyy-MM-dd HH:mm:ss}  режим: {1}", DateTime.Now,
                ScanMode ? "СКАН (-scan, без изменений)" : "ПОЛНЫЙ (правка hosts)"));
            Log("=====================================================================");

            if (!ScanMode && !IsAdministrator())
            {
                Log("Нет прав администратора — перезапуск с повышением (UAC)...");
                if (RelaunchElevated())
                {
                    Log("Экземпляр с правами администратора запущен, этот закрывается.");
                    return 0;
                }
                Log("ОШИБКА: повышение прав отклонено или не удалось. Изменения невозможны.");
                WaitAtEnd();
                return 1;
            }

            string hostsPath = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
            string backupPath = hostsPath + ".lolbypass.bak";
            Log("Файл hosts: " + hostsPath);

            string[] hostLines = null;
            try { hostLines = File.ReadAllLines(hostsPath); }
            catch (Exception ex) { Log("WARN: не удалось прочитать hosts: " + ex.Message); }

            Dictionary<string, string> existingPins = new Dictionary<string, string>();
            if (hostLines != null)
            {
                CollectExistingPins(hostLines, existingPins);
                foreach (KeyValuePair<string, string> kv in existingPins)
                {
                    Log("Найден существующий пин в hosts: " + kv.Key + " -> " + kv.Value);
                }
            }

            // Параллельная проверка всех хостов реестра (Task на каждый).
            HostResult[] results = new HostResult[HostRegistry.Length];
            Task[] tasks = new Task[HostRegistry.Length];
            int doneCount = 0;
            for (int i = 0; i < HostRegistry.Length; i++)
            {
                HostEntry entry = HostRegistry[i];
                int idx = i;
                string oldPin;
                if (!existingPins.TryGetValue(entry.Host, out oldPin)) oldPin = "";
                tasks[i] = Task.Factory.StartNew(delegate
                {
                    HostResult r = new HostResult();
                    r.Entry = entry;
                    r.PinnedIp = oldPin;
                    try { ProcessHost(r); }
                    catch (Exception ex)
                    {
                        LogFileOnly("ИСКЛЮЧЕНИЕ в задаче хоста " + entry.Host + ": " + ex.ToString());
                        r.DirectOk = false;
                        r.DirectError = "исключение: " + ex.Message;
                        r.ActionKind = 3;
                        r.Action = "FAIL-нет_обхода";
                    }
                    results[idx] = r;
                    int n = Interlocked.Increment(ref doneCount);
                    Log(string.Format("[{0}/{1}] {2}", n, HostRegistry.Length, ProgressLine(r)));
                });
            }

            // Диагностика чата (5223) — параллельно, только проверка.
            ChatResult[] chat = new ChatResult[ChatHosts.Length];
            Task[] chatTasks = new Task[ChatHosts.Length];
            for (int i = 0; i < ChatHosts.Length; i++)
            {
                string ch = ChatHosts[i];
                int ci = i;
                chatTasks[i] = Task.Factory.StartNew(delegate { chat[ci] = TestChat(ch); });
            }

            Task.WaitAll(tasks);
            Task.WaitAll(chatTasks);

            // Применение изменений — только в полном режиме.
            if (!ScanMode)
            {
                ApplyHostsChanges(hostsPath, backupPath, hostLines, results);
            }

            PrintTable(results);
            PrintChatSection(chat);
            PrintSummary(results);
            Log("Готово.");
            WaitAtEnd();
            return 0;
        }

        // ===================================================================
        //  Проверка одного хоста
        // ===================================================================
        private static void ProcessHost(HostResult r)
        {
            string host = r.Entry.Host;

            // (a) Резолвим имя (может вернуть IP из hosts-пина).
            try
            {
                IPAddress[] all = Dns.GetHostAddresses(host);
                foreach (IPAddress a in all)
                {
                    if (a.AddressFamily == AddressFamily.InterNetwork)
                    {
                        r.ResolvedV4.Add(a);
                    }
                }
            }
            catch (Exception ex)
            {
                r.DirectError = "DNS: " + ex.Message;
                LogFileOnly("DNS fail " + host + ": " + ex.Message);
            }

            // Кандидаты для прямого теста — все IPv4 КРОМЕ текущего пина из
            // hosts: если пин мёртв, а домен жив через обычный DNS, пин надо
            // снять; если жив только пин — обновить его.
            List<string> candidates = new List<string>();
            foreach (IPAddress a in r.ResolvedV4)
            {
                string s = a.ToString();
                if (r.PinnedIp.Length > 0 && string.Equals(s, r.PinnedIp, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                candidates.Add(s);
            }

            // (b) Прямой тест: ищем хоть один живой резолвленный IP (443).
            foreach (string ip in candidates)
            {
                long ms;
                string err;
                if (TestTls(ip, host, 443, out ms, out err))
                {
                    r.DirectOk = true;
                    r.DirectMs = ms;
                    break;
                }
                r.DirectError = err;
                LogFileOnly("direct fail " + host + " via " + ip + ": " + err);
            }
            if (!r.DirectOk && candidates.Count == 0 && r.DirectError.Length == 0)
            {
                r.DirectError = "нет IPv4";
            }

            // (c) Если напрямую мёртв — подбираем лучший обходной IP из пула CF.
            if (!r.DirectOk)
            {
                long avg;
                int alive;
                string best = FindBestBackupIp(host, out avg, out alive);
                if (best != null)
                {
                    r.BestIp = best;
                    r.BestAvgMs = avg;
                    r.BypassAliveCount = alive;
                }
            }

            // Итоговое действие.
            if (r.DirectOk && r.PinnedIp.Length == 0)
            {
                r.ActionKind = 0;
                r.Action = "OK-оставлено";
            }
            else if (r.DirectOk) // был пин, но домен жив напрямую без него
            {
                r.ActionKind = 2;
                r.Action = "REMOVED " + r.PinnedIp;
            }
            else if (r.BestIp.Length > 0)
            {
                r.ActionKind = 1;
                r.NewPinIp = r.BestIp;
                r.Action = string.Format("PIN {0} ({1} мс)", r.BestIp, r.BestAvgMs);
                if (r.PinnedIp.Length > 0)
                {
                    r.Action += " [был " + r.PinnedIp + "]";
                }
                r.Action += string.Format(", живых в пуле: {0}", r.BypassAliveCount);
            }
            else
            {
                r.ActionKind = 3;
                r.Action = "FAIL-нет_обхода";
            }
        }

        // ===================================================================
        //  Подбор лучшего резервного IP Cloudflare
        // ===================================================================
        private static string FindBestBackupIp(string host, out long bestAvgMs, out int aliveCount)
        {
            bestAvgMs = -1;
            aliveCount = 0;
            List<KeyValuePair<string, long>> ok = new List<KeyValuePair<string, long>>();
            object sync = new object();
            Task[] sweep = new Task[CfBackupPool.Length];

            for (int i = 0; i < CfBackupPool.Length; i++)
            {
                string ip = CfBackupPool[i];
                sweep[i] = Task.Factory.StartNew(delegate
                {
                    long ms;
                    string err;
                    if (TestTls(ip, host, 443, out ms, out err))
                    {
                        lock (sync)
                        {
                            ok.Add(new KeyValuePair<string, long>(ip, ms));
                        }
                    }
                    else
                    {
                        LogFileOnly("bypass fail " + host + " via " + ip + ": " + err);
                    }
                });
            }
            Task.WaitAll(sweep);

            if (ok.Count == 0)
            {
                return null;
            }
            aliveCount = ok.Count;
            ok.Sort(delegate(KeyValuePair<string, long> a, KeyValuePair<string, long> b)
            {
                return a.Value.CompareTo(b.Value);
            });

            // Топ-3 по скорости, перепроверка по 2 раза последовательно.
            int top = Math.Min(3, ok.Count);
            string bestIp = null;
            long bestAvg = long.MaxValue;
            for (int i = 0; i < top; i++)
            {
                string ip = ok[i].Key;
                long sum = 0;
                int good = 0;
                for (int t = 0; t < 2; t++)
                {
                    long ms;
                    string err;
                    if (TestTls(ip, host, 443, out ms, out err))
                    {
                        sum += ms;
                        good++;
                    }
                    else
                    {
                        LogFileOnly("retest fail " + host + " via " + ip + ": " + err);
                    }
                }
                if (good == 0)
                {
                    continue;
                }
                long avg = sum / good;
                if (avg < bestAvg)
                {
                    bestAvg = avg;
                    bestIp = ip;
                }
            }
            if (bestIp == null)
            {
                // Топ-3 не прошли перепроверку — берём самый быстрый первого прохода.
                bestIp = ok[0].Key;
                bestAvg = ok[0].Value;
                LogFileOnly("retest: все топ-IP не подтвердились, " + host + " -> fallback " + bestIp);
            }
            bestAvgMs = bestAvg;
            return bestIp;
        }

        // ===================================================================
        //  TCP connect + TLS handshake (SNI = имя хоста), таймауты 4000/4000
        // ===================================================================
        private static bool TestTls(string ip, string sniHost, int port, out long elapsedMs, out string error)
        {
            elapsedMs = -1;
            error = "";
            TcpClient client = new TcpClient();
            SslStream ssl = null;
            try
            {
                IAsyncResult connectAr = client.BeginConnect(ip, port, null, null);
                if (!connectAr.AsyncWaitHandle.WaitOne(ConnectTimeoutMs))
                {
                    error = "TCP: таймаут connect";
                    return false;
                }
                client.EndConnect(connectAr);

                ssl = new SslStream(client.GetStream(), false,
                    new RemoteCertificateValidationCallback(delegate { return true; }), null);

                Stopwatch sw = Stopwatch.StartNew();
                Task authTask = Task.Factory.StartNew(delegate
                {
                    ssl.AuthenticateAsClient(sniHost, null,
                        SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12, false);
                });
                bool finished;
                try { finished = authTask.Wait(TlsTimeoutMs); }
                catch (AggregateException ag)
                {
                    error = "TLS: " + ag.GetBaseException().Message;
                    return false;
                }
                if (!finished)
                {
                    error = "TLS: таймаут handshake";
                    authTask.ContinueWith(delegate(Task t)
                    {
                        if (t.Exception != null)
                        {
                            LogFileOnly("TLS фоновая ошибка (" + sniHost + " via " + ip + "): " +
                                t.Exception.GetBaseException().Message);
                        }
                    }, TaskContinuationOptions.OnlyOnFaulted);
                    return false;
                }
                sw.Stop();
                elapsedMs = sw.ElapsedMilliseconds;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            finally
            {
                if (ssl != null)
                {
                    try { ssl.Dispose(); }
                    catch (Exception ex) { LogFileOnly("ssl dispose (" + ip + "): " + ex.Message); }
                }
                try { client.Close(); }
                catch (Exception ex) { LogFileOnly("tcp close (" + ip + "): " + ex.Message); }
            }
        }

        // ===================================================================
        //  Диагностика чат-серверов (порт 5223) — только проверка
        // ===================================================================
        private static ChatResult TestChat(string host)
        {
            ChatResult c = new ChatResult();
            c.Host = host;
            try
            {
                IPAddress[] all = Dns.GetHostAddresses(host);
                IPAddress v4 = null;
                foreach (IPAddress a in all)
                {
                    if (a.AddressFamily == AddressFamily.InterNetwork)
                    {
                        v4 = a;
                        break;
                    }
                }
                if (v4 == null)
                {
                    c.Error = "DNS: нет IPv4-адреса";
                    return c;
                }
                long ms;
                string err;
                if (TestTls(v4.ToString(), host, 5223, out ms, out err))
                {
                    c.Ok = true;
                    c.Ms = ms;
                }
                else
                {
                    c.Error = err;
                }
            }
            catch (Exception ex)
            {
                c.Error = "DNS: " + ex.Message;
                LogFileOnly("chat DNS fail " + host + ": " + ex.Message);
            }
            return c;
        }

        // ===================================================================
        //  hosts: поиск существующих пинов по реестру
        // ===================================================================
        private static void CollectExistingPins(string[] lines, Dictionary<string, string> pins)
        {
            Dictionary<string, bool> names = new Dictionary<string, bool>();
            foreach (HostEntry e in HostRegistry)
            {
                names[e.Host] = true;
            }
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#"))
                {
                    continue;
                }
                string[] tokens = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2)
                {
                    continue;
                }
                IPAddress ip;
                if (!IPAddress.TryParse(tokens[0], out ip))
                {
                    continue;
                }
                for (int i = 1; i < tokens.Length; i++)
                {
                    string tok = tokens[i].ToLowerInvariant();
                    if (names.ContainsKey(tok))
                    {
                        if (!pins.ContainsKey(tok))
                        {
                            pins[tok] = tokens[0];
                        }
                        break;
                    }
                }
            }
        }

        // ===================================================================
        //  hosts: применение изменений (только полный режим)
        // ===================================================================
        private static void ApplyHostsChanges(string hostsPath, string backupPath, string[] originalLines, HostResult[] results)
        {
            if (originalLines == null)
            {
                Log("ОШИБКА: hosts не был прочитан — изменения не применены.");
                return;
            }

            List<KeyValuePair<string, string>> newPins = new List<KeyValuePair<string, string>>();
            foreach (HostResult r in results)
            {
                if (r != null && r.ActionKind == 1 && r.NewPinIp.Length > 0)
                {
                    newPins.Add(new KeyValuePair<string, string>(r.NewPinIp, r.Entry.Host));
                }
            }

            List<string> removedLines = new List<string>();
            List<string> newLines = BuildNewHostContent(originalLines, newPins, removedLines);

            if (LinesEqual(originalLines, newLines))
            {
                Log("hosts не требует изменений — запись и сброс DNS пропущены.");
                return;
            }

            try
            {
                File.Copy(hostsPath, backupPath, true);
                Log("Сделан бэкап: " + backupPath);
            }
            catch (Exception ex)
            {
                Log("ОШИБКА: не удалось создать бэкап hosts, изменения отменены: " + ex.Message);
                return;
            }

            foreach (string removed in removedLines)
            {
                Log("Удалено из hosts: " + removed);
            }

            StringBuilder sb = new StringBuilder();
            foreach (string l in newLines)
            {
                sb.Append(l);
                sb.Append("\r\n");
            }
            try
            {
                File.WriteAllText(hostsPath, sb.ToString(), Encoding.ASCII);
                Log(string.Format("hosts записан: добавлено пинов: {0}, удалено строк: {1}",
                    newPins.Count, removedLines.Count));
            }
            catch (Exception ex)
            {
                Log("ОШИБКА записи hosts: " + ex.Message + " (бэкап: " + backupPath + ")");
                return;
            }

            FlushDns();
        }

        private static List<string> BuildNewHostContent(string[] originalLines,
            List<KeyValuePair<string, string>> newPins, List<string> removedLines)
        {
            Dictionary<string, bool> names = new Dictionary<string, bool>();
            foreach (HostEntry e in HostRegistry)
            {
                names[e.Host] = true;
            }

            List<string> output = new List<string>();
            bool inBlock = false;
            foreach (string raw in originalLines)
            {
                string trimmed = raw.Trim();
                if (trimmed == BlockStart)
                {
                    inBlock = true;
                    removedLines.Add(raw);
                    continue;
                }
                if (trimmed == BlockEnd)
                {
                    inBlock = false;
                    removedLines.Add(raw);
                    continue;
                }
                if (inBlock)
                {
                    removedLines.Add(raw);
                    continue;
                }
                if (IsManagedPinLine(trimmed, names))
                {
                    removedLines.Add(raw);
                    continue;
                }
                output.Add(raw);
            }

            if (newPins.Count > 0)
            {
                if (output.Count > 0 && output[output.Count - 1].Trim().Length > 0)
                {
                    output.Add("");
                }
                output.Add(BlockStart);
                foreach (KeyValuePair<string, string> p in newPins)
                {
                    output.Add(p.Key + "\t" + p.Value);
                }
                output.Add(BlockEnd);
            }
            return output;
        }

        // Строка вида "IP ... имя_из_реестра" (первый токен — IP, дикие карты
        // вида *.name и комментарии не совпадают по точному равенству).
        private static bool IsManagedPinLine(string trimmedLine, Dictionary<string, bool> names)
        {
            if (trimmedLine.Length == 0 || trimmedLine.StartsWith("#"))
            {
                return false;
            }
            string[] tokens = trimmedLine.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2)
            {
                return false;
            }
            IPAddress ip;
            if (!IPAddress.TryParse(tokens[0], out ip))
            {
                return false;
            }
            for (int i = 1; i < tokens.Length; i++)
            {
                if (names.ContainsKey(tokens[i].ToLowerInvariant()))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool LinesEqual(string[] a, List<string> b)
        {
            if (a == null)
            {
                return b == null || b.Count == 0;
            }
            if (a.Length != b.Count)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        private static void FlushDns()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(Environment.SystemDirectory, "ipconfig.exe");
                psi.Arguments = "/flushdns";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    string outp = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(15000);
                    Log("Кэш DNS сброшен (ipconfig /flushdns): " + outp.Trim());
                }
            }
            catch (Exception ex)
            {
                Log("WARN: не удалось выполнить ipconfig /flushdns: " + ex.Message);
            }
        }

        // ===================================================================
        //  Отчёт
        // ===================================================================
        private static void PrintTable(HostResult[] results)
        {
            Log("");
            Log("==========================================================================");
            Log(string.Format("ИТОГОВАЯ ТАБЛИЦА ({0} хостов)", results.Length));
            Log("==========================================================================");
            Log("Хост".PadRight(42) + "Прямой тест".PadRight(16) + "Действие");
            Log("--------------------------------------------------------------------------");
            foreach (HostResult r in results)
            {
                if (r == null)
                {
                    continue;
                }
                string hostCol = r.Entry.Host + (r.Entry.Critical ? " [CRIT]" : "");
                string directCol = r.DirectOk ? string.Format("OK ({0} мс)", r.DirectMs) : "FAIL";
                Log(hostCol.PadRight(42) + directCol.PadRight(16) + r.Action);
            }
            Log("--------------------------------------------------------------------------");
        }

        private static void PrintChatSection(ChatResult[] chat)
        {
            Log("");
            Log("=== ДИАГНОСТИКА ЧАТА (порт 5223, напрямую; hosts это не чинит) ===");
            bool anyFail = false;
            foreach (ChatResult c in chat)
            {
                if (c == null)
                {
                    continue;
                }
                if (c.Ok)
                {
                    Log(string.Format("{0}: OK ({1} мс)", c.Host, c.Ms));
                }
                else
                {
                    Log(string.Format("{0}: FAIL ({1})", c.Host, c.Error));
                    anyFail = true;
                }
            }
            if (anyFail)
            {
                Log("Подсказка: порт 5223 режется DPI — нужен zapret (filter-tcp 5223 syndata); hosts это не чинит.");
            }
        }

        private static void PrintSummary(HostResult[] results)
        {
            int direct = 0, pinned = 0, removed = 0, failed = 0;
            List<string> failList = new List<string>();
            List<string> critFailList = new List<string>();
            foreach (HostResult r in results)
            {
                if (r == null)
                {
                    continue;
                }
                if (r.DirectOk)
                {
                    direct++;
                }
                switch (r.ActionKind)
                {
                    case 1: pinned++; break;
                    case 2: removed++; break;
                    case 3:
                        failed++;
                        failList.Add(r.Entry.Host + (r.Entry.Critical ? " [CRIT]" : ""));
                        if (r.Entry.Critical)
                        {
                            critFailList.Add(r.Entry.Host);
                        }
                        break;
                }
            }
            Log("");
            Log(string.Format("Сводка: Прямо: {0}, Прописано: {1}, Убрано пинов: {2}, Не чинится: {3}{4}",
                direct, pinned, removed, failed,
                ScanMode ? "  (режим -scan: изменения не применялись)" : ""));
            if (failList.Count > 0)
            {
                Log("Не чинится: " + string.Join(", ", failList.ToArray()));
            }
            if (critFailList.Count > 0)
            {
                Log("ВНИМАНИЕ, критичные для входа хосты без доступа: " + string.Join(", ", critFailList.ToArray()));
            }
        }

        private static string ProgressLine(HostResult r)
        {
            string crit = r.Entry.Critical ? " [CRIT]" : "";
            if (r.DirectOk)
            {
                return string.Format("{0}{1}: прямой OK ({2} мс) -> {3}", r.Entry.Host, crit, r.DirectMs, r.Action);
            }
            if (r.BestIp.Length > 0)
            {
                return string.Format("{0}{1}: прямой FAIL -> {2}", r.Entry.Host, crit, r.Action);
            }
            return string.Format("{0}{1}: прямой FAIL ({2}) -> {3}", r.Entry.Host, crit, r.DirectError, r.Action);
        }

        // ===================================================================
        //  Права администратора / перезапуск / завершение / лог
        // ===================================================================
        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                if (identity == null)
                {
                    return false;
                }
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                LogFileOnly("Проверка прав администратора не удалась: " + ex.Message);
                return false;
            }
        }

        private static bool RelaunchElevated()
        {
            try
            {
                string exePath = Assembly.GetExecutingAssembly().Location;
                if (string.IsNullOrEmpty(exePath))
                {
                    try { exePath = Process.GetCurrentProcess().MainModule.FileName; }
                    catch (Exception ex) { LogFileOnly("MainModule недоступен: " + ex.Message); }
                }
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = exePath;
                psi.Verb = "runas";
                psi.UseShellExecute = true;
                psi.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                LogFileOnly("Не удалось запустить процесс с повышением прав: " + ex.Message);
                return false;
            }
        }

        private static void WaitAtEnd()
        {
            // При перенаправленном stdin (например, "< NUL") клавишу не ждём.
            if (Console.IsInputRedirected)
            {
                LogFileOnly("stdin перенаправлен — ожидание клавиши пропущено");
                return;
            }
            try
            {
                Console.Write("Нажмите любую клавишу для выхода...");
                Console.ReadKey(true);
                Console.WriteLine();
            }
            catch (InvalidOperationException ex)
            {
                LogFileOnly("ReadKey недоступен: " + ex.Message);
            }
        }

        private static void Log(string line)
        {
            string stamped = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + line;
            lock (LogSync)
            {
                bool consoleOk = true;
                try { Console.WriteLine(line); }
                catch (Exception ex)
                {
                    consoleOk = false;
                    stamped = stamped + " [console: " + ex.Message + "]";
                }
                try { File.AppendAllText(LogPath, stamped + "\r\n", Encoding.UTF8); }
                catch (Exception ex)
                {
                    if (consoleOk)
                    {
                        WarnConsoleOnly("WARN: не удалось записать лог: " + ex.Message);
                    }
                }
            }
        }

        private static void LogFileOnly(string line)
        {
            string stamped = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + line;
            lock (LogSync)
            {
                try { File.AppendAllText(LogPath, stamped + "\r\n", Encoding.UTF8); }
                catch (Exception ex) { WarnConsoleOnly("WARN: не удалось записать лог: " + ex.Message); }
            }
        }

        private static void WarnConsoleOnly(string line)
        {
            try { Console.WriteLine(line); }
            catch (Exception ex) { throw new InvalidOperationException("Консоль недоступна: " + line, ex); }
        }
    }
}
