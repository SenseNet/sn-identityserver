using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.IdentityServer4
{
    /// <summary>
    /// Defines methods for the registration process.
    /// </summary>
    public interface IRegistrationManager
    {
        /// <summary>
        /// Perform additional operations after registration (in snaas: assign a new repository).
        /// </summary>
        /// <param name="connector">Predefined sensenet client connector.</param>
        /// <param name="user">The newly registered user.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        Task OnRegistrationConfirmedAsync(SnClientConnector connector, SnUser user, CancellationToken cancel);

        /// <summary>
        /// Perform additional operations after an external registration process (e.g. Google or GitHub)
        /// completed (in snaas: assign a new repository).
        /// </summary>
        /// <param name="connector">Predefined sensenet client connector.</param>
        /// <param name="user">The newly registered user.</param>
        /// <param name="password">The new password.</param>
        /// <param name="cancel">The token to monitor for cancellation requests.</param>
        /// <returns>A Task that represents the asynchronous operation.</returns>
        Task OnExternalRegistrationCompletedAsync(SnClientConnector connector, SnUser user, string password, CancellationToken cancel);
        /// <summary>
        /// Whether to redirect to the create repository page where the user will have to provide
        /// a password to set for the first public admin user in the new repository.
        /// </summary>
        /// <param name="connector">Predefined sensenet client connector.</param>
        /// <returns>A Task that represents the asynchronous operation and wraps the result boolean value.</returns>
        bool ExternalRegistrationRedirectToPasswordForm(SnClientConnector connector);
    }

    public class DefaultRegistrationManager : IRegistrationManager
    {
        public Task OnRegistrationConfirmedAsync(SnClientConnector connector, SnUser user, CancellationToken cancel)
        {
            return Task.CompletedTask;
        }

        public Task OnExternalRegistrationCompletedAsync(SnClientConnector connector, SnUser user, string password,
            CancellationToken cancel)
        {
            return Task.CompletedTask;
        }

        public bool ExternalRegistrationRedirectToPasswordForm(SnClientConnector connector)
        {
            return false;
        }
    }
}
