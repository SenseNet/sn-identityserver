export const loadTermsOfUse = () => {
  const termsOfUseUrl = `https://sncom.service.sensenet.com/odata.svc/Root/Content/SensenetDotCom/pages/terms-of-use/('terms-of-use-20200924')?$select=Body&metadata=no`;

  const scrollArea = document.getElementById('termsContainer');

  fetch(termsOfUseUrl, {
    method: 'GET',
    cache: 'no-cache',
    credentials: 'include',
    headers: {
      Accept: 'application/json',
    },
  })
    .then((response) => response.json())
    .then((data) => {
      const text = data?.d.Body || 'Terms of use cannot be loaded. Please try to open with the link below.';
      scrollArea.innerHTML = text;
    });
};
