using System.Threading;
using System.Threading.Tasks;

namespace SenseNet.IdentityServer4.Web.Captcha
{
    public interface IRecaptchaService
    {
        Task<bool> VerifyAsync(string recaptchaResponse, string expectedAction, CancellationToken cancel);
    }
}
