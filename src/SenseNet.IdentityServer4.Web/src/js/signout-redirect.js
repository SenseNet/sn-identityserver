﻿export const signoutRedirect = () => {
  window.addEventListener('load', () => {
    const a = document.querySelector('a.PostLogoutRedirectUri');
    if (a) {
      window.location = a.href;
    }
  });
};
