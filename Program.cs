using CretaceousApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();

builder.Services.AddDbContext<CretaceousApiContext>(dbContextOptions =>
{
    dbContextOptions.UseMySql(
        builder.Configuration["ConnectionStrings:DefaultConnection"],
        ServerVersion.AutoDetect(builder.Configuration["ConnectionStrings:DefaultConnection"])
    );
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://www.yogihosting.com", // Set your issuer
        ValidAudience = "https://www.yogihosting.com", // Set your audience
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MynameisJamesBond007MynameisJamesBond007MynameisJamesBond007")) // Set your secret key
    };
});

// Add Swagger services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Development environment settings
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHttpsRedirection();
}

app.UseRouting();
app.UseAuthentication(); // Add this line for authentication
app.UseAuthorization();

app.MapControllers();

app.Run();
