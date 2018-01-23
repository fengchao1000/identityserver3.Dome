using IdentityServer3.Core.Logging;
using IdentityServer3.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace OIDC.IdentityServer.Web.CustomService
{ 
    public class TokenCleanupService
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        EntityFrameworkServiceOptions options;
        CancellationTokenSource source;
        TimeSpan interval;

        public TokenCleanupService(EntityFrameworkServiceOptions options, int interval = 60)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (interval < 1) throw new ArgumentException("interval must be more than 1 second");

            this.options = options;
            this.interval = TimeSpan.FromSeconds(interval);
        }

        public void Start()
        {
            if (source != null) throw new InvalidOperationException("Already started. Call Stop first.");

            source = new CancellationTokenSource();
            Task.Factory.StartNew(() => Start(source.Token));
        }

        public void Stop()
        {
            if (source == null) throw new InvalidOperationException("Not started. Call Start first.");

            source.Cancel();
            source = null;
        }

        public async Task Start(CancellationToken cancellationToken)
        {
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    Logger.Info("CancellationRequested");
                    break;
                }

                try
                {
                    await Task.Delay(interval, cancellationToken);
                }
                catch
                {
                    Logger.Info("Task.Delay exception. exiting.");
                    break;
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    Logger.Info("CancellationRequested");
                    break;
                }

                await ClearTokens();
            }
        }

        public virtual IOperationalDbContext CreateOperationalDbContext()
        {
            return new OperationalDbContext(options.ConnectionString, options.Schema);
        }

        private async Task ClearTokens()
        {
            try
            {
                Logger.Info("Clearing tokens");
                using (var db = CreateOperationalDbContext())
                {
                    var query =
                        from token in db.Tokens
                        where token.Expiry < DateTimeOffset.UtcNow
                        select token;

                    db.Tokens.RemoveRange(query);

                    await db.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                Logger.ErrorException("Exception cleaning tokens", ex);
            }
        }
    }
}