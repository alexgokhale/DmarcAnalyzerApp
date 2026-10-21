using Amazon.RDS.Util;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace DmarcAnalyzer.Api.Data;

/// <summary>
/// Builds the one <see cref="NpgsqlDataSource"/> a process connects through, so
/// every mode authenticates the same way.
/// <para>
/// With <c>Database:IamAuth</c> on, the password is an RDS IAM authentication
/// token instead of a stored secret. A token is only valid for 15 minutes, so a
/// fixed connection string cannot carry one: Npgsql asks for a fresh token on a
/// timer and uses the latest for every new physical connection.
/// </para>
/// </summary>
public static class DatabaseDataSource
{
    public const string IamAuthKey = "Database:IamAuth";

    /// <summary>
    /// Well inside the 15 minute token lifetime, so a connection opened just
    /// before a refresh still logs in with a valid token.
    /// </summary>
    private static readonly TimeSpan TokenRefreshInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// After a failed refresh (credentials not yet available, a throttled call),
    /// try again soon rather than waiting out the full interval.
    /// </summary>
    private static readonly TimeSpan TokenRetryInterval = TimeSpan.FromSeconds(5);

    public static NpgsqlDataSource Create(IConfiguration configuration, string connectionString)
    {
        var builder = new NpgsqlDataSourceBuilder(connectionString);

        if (configuration.GetValue<bool>(IamAuthKey))
        {
            UseIamAuth(builder);
        }

        return builder.Build();
    }

    private static void UseIamAuth(NpgsqlDataSourceBuilder builder)
    {
        var settings = builder.ConnectionStringBuilder;

        if (string.IsNullOrEmpty(settings.Host) || string.IsNullOrEmpty(settings.Username))
        {
            throw new InvalidOperationException(
                "Database__IamAuth needs a host and username in the connection string: the " +
                "IAM token is signed for that exact host, port and database user.");
        }

        // Npgsql refuses a password alongside a password provider, but its message
        // does not say which setting to change.
        if (!string.IsNullOrEmpty(settings.Password))
        {
            throw new InvalidOperationException(
                "Database__IamAuth is on but the connection string contains a password. " +
                "Remove the password or disable IAM auth.");
        }

        // RDS rejects IAM logins over unencrypted connections.
        if (settings.SslMode is SslMode.Disable)
        {
            throw new InvalidOperationException(
                "Database__IamAuth requires TLS, but the connection string sets sslmode to disable. " +
                "RDS only accepts IAM logins over TLS.");
        }

        if (settings.SslMode is SslMode.Allow or SslMode.Prefer)
        {
            settings.SslMode = SslMode.Require;
        }

        // Region and credentials come from the SDK's ambient chain: the ECS task
        // role, an instance profile, or IRSA - the same chain the S3 source uses.
        // The token is signed for one host and port, so it is generated from the
        // settings Npgsql passes in: with several hosts in the connection string,
        // each host's pool gets its own settings rather than the whole list.
        builder.UsePeriodicPasswordProvider(
            async (hostSettings, _) => await RDSAuthTokenGenerator.GenerateAuthTokenAsync(
                hostSettings.Host!, hostSettings.Port, hostSettings.Username!),
            TokenRefreshInterval,
            TokenRetryInterval);
    }
}
