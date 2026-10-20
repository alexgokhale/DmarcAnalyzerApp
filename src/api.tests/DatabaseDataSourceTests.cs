using DmarcAnalyzer.Api.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace DmarcAnalyzer.Api.Tests;

/// <summary>
/// Building a data source doesn't connect, so these check the settings that are
/// used - not that a token is accepted.
/// </summary>
public sealed class DatabaseDataSourceTests
{
    private static IConfiguration Config(bool? iamAuth = null)
    {
        var values = new Dictionary<string, string?>();
        if (iamAuth is not null)
        {
            values[DatabaseDataSource.IamAuthKey] = iamAuth.Value ? "true" : "false";
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    [Fact]
    public void WithoutIamAuth_KeepsThePasswordAndSslMode()
    {
        using var dataSource = DatabaseDataSource.Create(
            Config(),
            "Host=db.example.com;Database=dmarc_analyzer;Username=alice;Password=s3cret;SSL Mode=Disable");

        var settings = new NpgsqlConnectionStringBuilder(dataSource.ConnectionString);

        Assert.Equal(SslMode.Disable, settings.SslMode);
        Assert.Equal("alice", settings.Username);
    }

    [Fact]
    public void WithIamAuth_RaisesPreferToRequire()
    {
        using var dataSource = DatabaseDataSource.Create(
            Config(iamAuth: true),
            "Host=db.example.com;Database=dmarc_analyzer;Username=dmarc;SSL Mode=Prefer");

        var settings = new NpgsqlConnectionStringBuilder(dataSource.ConnectionString);

        Assert.Equal(SslMode.Require, settings.SslMode);
    }

    [Fact]
    public void WithIamAuth_KeepsAStricterSslMode()
    {
        using var dataSource = DatabaseDataSource.Create(
            Config(iamAuth: true),
            "Host=db.example.com;Database=dmarc_analyzer;Username=dmarc;SSL Mode=VerifyFull");

        var settings = new NpgsqlConnectionStringBuilder(dataSource.ConnectionString);

        Assert.Equal(SslMode.VerifyFull, settings.SslMode);
    }

    [Fact]
    public void WithIamAuth_RefusesAPassword()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DatabaseDataSource.Create(
            Config(iamAuth: true),
            "Host=db.example.com;Database=dmarc_analyzer;Username=dmarc;Password=s3cret"));

        Assert.Contains("password", ex.Message);
    }

    [Fact]
    public void WithIamAuth_RefusesDisabledTls()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DatabaseDataSource.Create(
            Config(iamAuth: true),
            "Host=db.example.com;Database=dmarc_analyzer;Username=dmarc;SSL Mode=Disable"));

        Assert.Contains("TLS", ex.Message);
    }

    [Fact]
    public void WithIamAuth_RefusesAMissingUsername()
    {
        Assert.Throws<InvalidOperationException>(() => DatabaseDataSource.Create(
            Config(iamAuth: true),
            "Host=db.example.com;Database=dmarc_analyzer"));
    }

    [Fact]
    public void IamAuthOff_IsTheSameAsUnset()
    {
        using var dataSource = DatabaseDataSource.Create(
            Config(iamAuth: false),
            "Host=db.example.com;Database=dmarc_analyzer;Username=alice;Password=s3cret");

        Assert.Equal("alice", new NpgsqlConnectionStringBuilder(dataSource.ConnectionString).Username);
    }
}
