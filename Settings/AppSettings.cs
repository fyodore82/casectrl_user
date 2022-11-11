namespace CaseCTRLAPI.Settings
{
    public class CustomIdentity
    {
        public string? ClientUrl { get; set; }
    }

    public class EmailServer
    {
        public string? EmailServerDns { get; set; }
        public int? Port { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }

    }

    public class Jwt
    {
        public string? Key { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
    }

    public class AppSettings
    {
        public AppSettings ()
        {
            CustomIdentity = new CustomIdentity();
            EmailServer = new EmailServer ();
            Jwt = new Jwt();
        }
        public CustomIdentity CustomIdentity { get; set; }
        public EmailServer EmailServer { get; set; }
        public Jwt Jwt { get; set; }
    }
}
