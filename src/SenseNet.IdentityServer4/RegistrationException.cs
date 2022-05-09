using System;

namespace SenseNet.IdentityServer4
{
    public enum RegistrationError
    {
        ServiceNotAvailable,
        LimitExceeded,
        ExistingUser,
        InvalidContent,
        InvalidClientAfterRegistration
    }

    [Serializable]
    public class RegistrationException : Exception
    {
        public RegistrationError Error { get; }
        public RegistrationException(RegistrationError error, Exception innerException = null) : base(GetMessage(error), innerException)
        {
            Error = error;
        }

        public RegistrationException() {}
        public RegistrationException(string message) : base(message) {}
        public RegistrationException(string message, Exception innerException) : base(message, innerException) {}
        protected RegistrationException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }

        public static string GetMessage(RegistrationError error)
        {
            return error switch
            {
                RegistrationError.LimitExceeded =>
                "One of the repository limitations is exceeded, please contact the repository owner.",
                RegistrationError.ExistingUser =>
                "A user is already registered with the provided username, try to log in instead.",
                RegistrationError.InvalidContent => "Invalid registration values.",
                RegistrationError.InvalidClientAfterRegistration => "Registration is successful, but you cannot log in using this client.",
                _ => "There was an error during registration. The service may be inaccessible.",
            };
        }
    }
}
