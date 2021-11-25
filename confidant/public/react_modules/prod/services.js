
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Resources = function (_React$Component) {
  _inherits(Resources, _React$Component);

  function Resources(props) {
    _classCallCheck(this, Resources);

    var _this = _possibleConstructorReturn(this, (Resources.__proto__ || Object.getPrototypeOf(Resources)).call(this, props));

    _this.filter = function (resourceType) {
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
        React.createElement(Buttons, { onClickity: this.filter }),
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

      return React.createElement(
        'div',
        { className: 'col-md-9' },
        buttons.map(function (type, i) {
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
        })
      );
    }
  }]);

  return Buttons;
}(React.Component);

var ServicesList = function (_React$Component3) {
  _inherits(ServicesList, _React$Component3);

  function ServicesList(props) {
    _classCallCheck(this, ServicesList);

    var _this4 = _possibleConstructorReturn(this, (ServicesList.__proto__ || Object.getPrototypeOf(ServicesList)).call(this, props));

    _this4.state = {};
    return _this4;
  }

  _createClass(ServicesList, [{
    key: 'componentDidMount',
    value: function componentDidMount() {
      var _this5 = this;

      fetch("/v1/services").then(function (res) {
        return res.json();
      }).then(function (result) {
        console.log(result.services);
        _this5.setState({
          isLoaded: true,
          resources: result.services
        });
      },
      // Note: it's important to handle errors here
      // instead of a catch() block so that we don't swallow
      // exceptions from actual bugs in components.
      function (error) {
        _this5.setState({
          isLoaded: true,
          error: error
        });
      });
    }
  }, {
    key: 'render',
    value: function render() {
      var _this6 = this;

      var _state2 = this.state,
          error = _state2.error,
          isLoaded = _state2.isLoaded,
          resources = _state2.resources;

      if (error) {
        return React.createElement(
          'div',
          null,
          'Error: ',
          error.message
        );
      } else if (!isLoaded) {
        return React.createElement(
          'tr',
          null,
          React.createElement(
            'td',
            null,
            'Loading...'
          )
        );
      } else {
        return resources.map(function (resource) {
          return React.createElement(
            'tr',
            { key: resource.id, style: { cursor: "pointer" }, className: _this6.props.filter.resourceType != "services" ? "ng-hide" : "" },
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
    }
  }]);

  return ServicesList;
}(React.Component);

var CredentialsList = function (_React$Component4) {
  _inherits(CredentialsList, _React$Component4);

  function CredentialsList(props) {
    _classCallCheck(this, CredentialsList);

    var _this7 = _possibleConstructorReturn(this, (CredentialsList.__proto__ || Object.getPrototypeOf(CredentialsList)).call(this, props));

    _this7.state = {};
    return _this7;
  }

  _createClass(CredentialsList, [{
    key: 'componentDidMount',
    value: function componentDidMount() {
      var _this8 = this;

      fetch("/v1/credentials").then(function (res) {
        return res.json();
      }).then(function (result) {
        console.log(result);
        _this8.setState({
          isLoaded: true,
          resources: result.credentials
        });
      },
      // Note: it's important to handle errors here
      // instead of a catch() block so that we don't swallow
      // exceptions from actual bugs in components.
      function (error) {
        _this8.setState({
          isLoaded: true,
          error: error
        });
      });
    }
  }, {
    key: 'render',
    value: function render() {
      var _this9 = this;

      var _state3 = this.state,
          error = _state3.error,
          isLoaded = _state3.isLoaded,
          resources = _state3.resources;

      if (error) {
        return React.createElement(
          'div',
          null,
          'Error: ',
          error.message
        );
      } else if (!isLoaded) {
        return React.createElement(
          'tr',
          null,
          React.createElement(
            'td',
            null,
            'Loading...'
          )
        );
      } else {
        return resources.map(function (resource) {
          return React.createElement(
            'tr',
            { key: resource.id, onClick: function onClick() {
                return console.log('clicked');
              }, style: { cursor: "pointer" }, className: _this9.props.filter.resourceType != "credentials" ? "ng-hide" : "" },
            React.createElement(
              'td',
              { className: 'dont-break-out' },
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
    }
  }]);

  return CredentialsList;
}(React.Component);

ReactDOM.render(React.createElement(Resources, null), document.getElementById('like_button_container'));