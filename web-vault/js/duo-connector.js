!(function () {
    var frameElement = document.createElement('iframe');
    frameElement.setAttribute('id', 'duo_iframe');
    setFrameHeight();
    document.body.appendChild(frameElement);

    var hostParam = getQsParam('host');
    var requestParam = getQsParam('request');
    Duo.init({
        host: hostParam,
        sig_request: requestParam,
        submit_callback: function (form) {
            invokeCSCode(form.elements.sig_response.value);
        }
    });

    window.onresize = setFrameHeight;
    function setFrameHeight() {
        frameElement.style.height = window.innerHeight + 'px';
    }
})();

function getQsParam(name) {
    var url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

function invokeCSCode(data) {
    try {
        invokeCSharpAction(data);
    }
    catch (err) {

    }
}
