using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Configuration;
using System.Net.Mail;
using System.Net;
using Microsoft.AspNetCore.Identity.UI.Services;
using CaseCTRLAPI.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using CaseCTRLAPI.Settings;
using Microsoft.Extensions.DependencyInjection;
using Users;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("AuthenticationContextConnection") ?? throw new InvalidOperationException("Connection string 'AuthenticationContextConnection' not found.");

builder.Services.AddDbContext<AuthenticationContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDefaultIdentity<Authentication>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<AuthenticationContext>();
var allOriginsPolicy = "All origins";
builder.Services.AddCors(options =>
{
    options.AddPolicy(allOriginsPolicy, builder =>
    {
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("CustomSettings"));
var appSettings = builder.Configuration.GetSection("CustomSettings").Get<AppSettings>();

builder.Services.AddSingleton(new SmtpClient(appSettings.EmailServer.EmailServerDns)
{
    Port = appSettings.EmailServer.Port ?? 25,
    Credentials = new NetworkCredential(appSettings.EmailServer.Username, appSettings.EmailServer.Password),
    EnableSsl = true,
});

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = appSettings.Jwt.Issuer,
        ValidAudience = appSettings.Jwt.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appSettings.Jwt.Key))
    };
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseCors(allOriginsPolicy);

app.MapControllers();

app.Run();
