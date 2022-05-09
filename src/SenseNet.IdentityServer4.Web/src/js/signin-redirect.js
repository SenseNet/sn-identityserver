export const signinRedirect = () => {
  window.location.href = document.querySelector('meta[http-equiv=refresh]').getAttribute('data-url');
};
