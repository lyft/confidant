var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

import AppWrapper from './resources.js';
var _ReactRouterDOM = ReactRouterDOM,
    BrowserRouter = _ReactRouterDOM.BrowserRouter,
    Switch = _ReactRouterDOM.Switch,
    Redirect = _ReactRouterDOM.Redirect,
    Router = _ReactRouterDOM.Router;
var _React = React,
    useEffect = _React.useEffect,
    useState = _React.useState;


function waitForElm(selector) {
    return new Promise(function (resolve) {
        if (document.querySelector(selector)) {
            return resolve(document.querySelector(selector));
        }

        var observer = new MutationObserver(function (mutations) {
            if (document.querySelector(selector)) {
                resolve(document.querySelector(selector));
                observer.disconnect();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    });
}

// todo cleanup, move into 
waitForElm('#reactDiv').then(function (elm) {
    console.log('Element is ready');
    console.log(elm.textContent);
    ReactDOM.render(React.createElement(AppWrapper, null), document.getElementById('reactDiv'));
});

var Header = function Header(props) {
    var _useState = useState(),
        _useState2 = _slicedToArray(_useState, 2),
        userEmail = _useState2[0],
        setUserEmail = _useState2[1];

    useEffect(function () {
        fetch('v1/user/email').then(function (res) {
            return res.json();
        }).then(function (result) {
            setUserEmail(result.email);
        },
        // Note: it's important to handle errors here
        // instead of a catch() block so that we don't swallow
        // exceptions from actual bugs in components.
        function (error) {});
    }, []);

    return React.createElement(
        'div',
        null,
        React.createElement('div', { id: 'loading-spinner', 'loading-spinner': 'data-loading' }),
        React.createElement(
            'header',
            { id: 'page-header', className: 'header' },
            React.createElement(
                'nav',
                { id: 'site-navigation' },
                React.createElement(
                    'div',
                    { className: 'container-fluid' },
                    React.createElement(
                        'p',
                        { className: 'navbar-text pull-right',
                            style: { textAlign: "right" }
                        },
                        'Logged in as ',
                        userEmail,
                        ' | ',
                        React.createElement(
                            'a',
                            { href: 'loggedout' },
                            'Log Out ',
                            React.createElement('span', { className: 'glyphicon glyphicon-log-out' })
                        )
                    ),
                    React.createElement(
                        'h1',
                        null,
                        React.createElement(
                            'a',
                            { href: '#' },
                            React.createElement('img', { className: 'site-logo visible-sm visible-md visible-lg', src: 'images/logo.svg' })
                        )
                    )
                )
            )
        )
    );
};

var Navigation = function Navigation(props) {
    return React.createElement(
        'div',
        null,
        React.createElement(Header, null)
    );
};

var Wrap = function Wrap() {
    return React.createElement(
        BrowserRouter,
        { forceRefresh: true },
        React.createElement(Navigation, null)
    );
};

ReactDOM.render(React.createElement(Wrap, null), document.getElementById('mainReactDiv'));