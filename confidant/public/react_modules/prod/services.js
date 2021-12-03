var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Link = ReactRouterDOM.Link;

// let { BrowserRouter, Switch, Redirect, Route } = ReactRouterDOM;
var _ReactRouterDOM = ReactRouterDOM,
    BrowserRouter = _ReactRouterDOM.BrowserRouter,
    Switch = _ReactRouterDOM.Switch,
    Redirect = _ReactRouterDOM.Redirect,
    Router = _ReactRouterDOM.Router;
var _ReactRouterDOM2 = ReactRouterDOM,
    useHistory = _ReactRouterDOM2.useHistory,
    useLocation = _ReactRouterDOM2.useLocation;
var _React = React,
    useEffect = _React.useEffect,
    useState = _React.useState;

{/* <Resources /> */}
var AppWrapper = function AppWrapper() {
  return React.createElement(
    BrowserRouter,
    { forceRefresh: true },
    React.createElement(Resources, null)
  );
};

var Resources = function (_React$Component) {
  _inherits(Resources, _React$Component);

  function Resources(props) {
    _classCallCheck(this, Resources);

    var _this = _possibleConstructorReturn(this, (Resources.__proto__ || Object.getPrototypeOf(Resources)).call(this, props));

    _this.searchFilter = function (searchText) {
      console.log('searching...' + searchText);
      _this.setState({
        searchText: searchText
      });
      console.log(_this.state);
    };

    _this.toggleType = function (resourceType) {
      console.log('filtering...' + resourceType);
      _this.setState({
        resourceType: resourceType
      });
      console.log(_this.state);
    };

    _this.state = {
      resourceType: 'credentials',
      searchText: ''
    };
    return _this;
  }

  _createClass(Resources, [{
    key: 'render',
    value: function render() {
      return React.createElement(
        'div',
        null,
        React.createElement(
          'div',
          { className: 'row' },
          React.createElement(
            'div',
            { className: 'form-group col-md-12' },
            React.createElement(SearchFilter, { onSearch: this.searchFilter })
          )
        ),
        React.createElement(
          'div',
          { className: 'row has-margin-bottom-lg' },
          React.createElement(
            'div',
            { className: 'col-md-9' },
            React.createElement(Buttons, { onClickity: this.toggleType })
          )
        ),
        React.createElement(
          'table',
          { className: 'table table-hover' },
          React.createElement(
            'thead',
            null,
            React.createElement(
              'tr',
              null,
              React.createElement(
                'th',
                null,
                'Name'
              ),
              React.createElement(
                'th',
                null,
                'Revision'
              ),
              React.createElement(
                'th',
                null,
                'Modified'
              ),
              React.createElement(
                'th',
                null,
                'Modified By'
              ),
              React.createElement('th', null)
            )
          ),
          React.createElement(
            'tbody',
            null,
            React.createElement(ServicesList, { filter: this.state }),
            React.createElement(CredentialsList, { filter: this.state })
          )
        )
      );
    }
  }]);

  return Resources;
}(React.Component);

function SearchFilter(props) {
  var _useState = useState(''),
      _useState2 = _slicedToArray(_useState, 2),
      value = _useState2[0],
      setValue = _useState2[1];

  var handleChange = function handleChange(event) {
    setValue(event.target.value);
    props.onSearch(event.target.value);
  };

  return React.createElement('input', {
    type: 'search',
    className: 'form-control',
    value: value,
    onChange: handleChange,
    placeholder: 'filter (credential, blind-credential, or service name)'
  });
}

var Buttons = function (_React$Component2) {
  _inherits(Buttons, _React$Component2);

  function Buttons(props) {
    _classCallCheck(this, Buttons);

    var _this2 = _possibleConstructorReturn(this, (Buttons.__proto__ || Object.getPrototypeOf(Buttons)).call(this, props));

    _this2.filterme = function (resourceType, index) {
      console.log(resourceType);
      _this2.setState({ activeIndex: index });
      _this2.props.onClickity(resourceType);
    };

    _this2.state = {
      buttons: [['credentials', 'Credentials'], ['blind_credentials', 'Blind Credentials'], ['services', 'Services']],
      activeIndex: 0
    };
    return _this2;
  }

  _createClass(Buttons, [{
    key: 'render',
    value: function render() {
      var _this3 = this;

      var _state = this.state,
          buttons = _state.buttons,
          activeIndex = _state.activeIndex;

      return buttons.map(function (type, i) {
        return React.createElement(
          'button',
          {
            key: type[0],
            type: 'button',
            className: i == activeIndex ? "btn active" : "btn",
            onClick: function onClick() {
              return _this3.filterme(type[0], i);
            } },
          type[1]
        );
      });
    }
  }]);

  return Buttons;
}(React.Component);

function ServicesList(props) {
  var _useState3 = useState(),
      _useState4 = _slicedToArray(_useState3, 2),
      resources = _useState4[0],
      setResources = _useState4[1];

  var _useState5 = useState(false),
      _useState6 = _slicedToArray(_useState5, 2),
      isLoaded = _useState6[0],
      setIsLoaded = _useState6[1];

  var _useState7 = useState(),
      _useState8 = _slicedToArray(_useState7, 2),
      error = _useState8[0],
      setError = _useState8[1];

  var history = useHistory();

  useEffect(function () {
    fetch("/v1/services").then(function (res) {
      return res.json();
    }).then(function (result) {
      setResources(result.services);
      setIsLoaded(true);
    },
    // Note: it's important to handle errors here
    // instead of a catch() block so that we don't swallow
    // exceptions from actual bugs in components.
    function (error) {
      setIsLoaded(true);
      setError(error);
    });
  }, []);

  var searchFilter = function searchFilter(searchTxt, resources) {
    var re = new RegExp(searchTxt, "g");
    var res = resources.filter(function (resource) {
      return re.test(resource.name);
    });
    return res;
  };

  if (!isLoaded) return React.createElement(
    'tr',
    null,
    React.createElement(
      'td',
      null,
      'Loading...'
    )
  );
  if (error) return React.createElement(
    'div',
    null,
    'Error: ',
    error.message
  );
  return searchFilter(props.filter.searchText, resources).map(function (resource) {
    return React.createElement(
      'tr',
      { key: resource.id,
        onClick: function onClick() {
          return history.push('#/resources/services/' + resource.id);
        },
        style: { cursor: "pointer" },
        className: props.filter.resourceType != "services" ? "ng-hide" : "" },
      React.createElement(
        'td',
        null,
        resource.id
      ),
      React.createElement(
        'td',
        null,
        resource.revision
      ),
      React.createElement(
        'td',
        null,
        resource.modified_date
      ),
      React.createElement(
        'td',
        null,
        resource.modified_by
      ),
      React.createElement(
        'td',
        null,
        React.createElement('span', { className: 'glyphicon glyphicon-menu-right' })
      )
    );
  });
}

function CredentialsList(props) {
  var _useState9 = useState(),
      _useState10 = _slicedToArray(_useState9, 2),
      resources = _useState10[0],
      setResources = _useState10[1];

  var _useState11 = useState(false),
      _useState12 = _slicedToArray(_useState11, 2),
      isLoaded = _useState12[0],
      setIsLoaded = _useState12[1];

  var _useState13 = useState(),
      _useState14 = _slicedToArray(_useState13, 2),
      error = _useState14[0],
      setError = _useState14[1];

  var history = useHistory();

  useEffect(function () {
    fetch("/v1/credentials").then(function (res) {
      return res.json();
    }).then(function (result) {
      setResources(result.credentials);
      setIsLoaded(true);
    },
    // Note: it's important to handle errors here
    // instead of a catch() block so that we don't swallow
    // exceptions from actual bugs in components.
    function (error) {
      setIsLoaded(true);
      setError(error);
    });
  }, []);

  var searchFilter = function searchFilter(searchTxt, resources) {
    var re = new RegExp(searchTxt, "g");
    var res = resources.filter(function (resource) {
      return re.test(resource.name);
    });
    console.log(searchTxt);
    console.log(resources);
    return res;
  };

  if (!isLoaded) return React.createElement(
    'tr',
    null,
    React.createElement(
      'td',
      null,
      'Loading...'
    )
  );
  if (error) return React.createElement(
    'div',
    null,
    'Error: ',
    error.message
  );
  return searchFilter(props.filter.searchText, resources).map(function (resource) {
    return React.createElement(
      'tr',
      { key: resource.id,
        onClick: function onClick() {
          return history.push('#/resources/credentials/' + resource.id);
        },
        style: { cursor: "pointer" },
        className: props.filter.resourceType != "credentials" ? "ng-hide" : "" },
      React.createElement(
        'td',
        null,
        resource.name
      ),
      React.createElement(
        'td',
        null,
        resource.revision
      ),
      React.createElement(
        'td',
        null,
        resource.modified_date
      ),
      React.createElement(
        'td',
        null,
        resource.modified_by
      ),
      React.createElement(
        'td',
        null,
        React.createElement('span', { className: 'glyphicon glyphicon-menu-right' })
      )
    );
  });
}

function ButtonTest() {
  console.log('test!!');
  var history = useHistory();
  // debugger
  console.log(history);
  var handleOnClick = function handleOnClick() {
    history.push('/#/resources/credentials/9d49d735c5a84510a332b8c929d3d265');
  };
  return React.createElement(
    'button',
    { type: 'button', onClick: handleOnClick },
    'Go home'
  );
}

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

export default AppWrapper;