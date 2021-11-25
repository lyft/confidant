'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var e = React.createElement;

var ServicesList = function (_React$Component) {
  _inherits(ServicesList, _React$Component);

  function ServicesList(props) {
    _classCallCheck(this, ServicesList);

    var _this = _possibleConstructorReturn(this, (ServicesList.__proto__ || Object.getPrototypeOf(ServicesList)).call(this, props));

    _this.state = { liked: false };
    return _this;
  }

  _createClass(ServicesList, [{
    key: "componentDidMount",
    value: function componentDidMount() {
      var _this2 = this;

      fetch("/v1/services").then(function (res) {
        return res.json();
      }).then(function (result) {
        console.log(result.services);
        _this2.setState({
          isLoaded: true,
          resources: result.services
        });
      },
      // Note: it's important to handle errors here
      // instead of a catch() block so that we don't swallow
      // exceptions from actual bugs in components.
      function (error) {
        _this2.setState({
          isLoaded: true,
          error: error
        });
      });
    }
  }, {
    key: "render",
    value: function render() {
      var _state = this.state,
          error = _state.error,
          isLoaded = _state.isLoaded,
          resources = _state.resources;

      if (error) {
        return React.createElement(
          "div",
          null,
          "Error: ",
          error.message
        );
      } else if (!isLoaded) {
        return React.createElement(
          "div",
          null,
          "Loading..."
        );
      } else {
        return React.createElement(
          "table",
          { className: "table table-hover" },
          React.createElement(
            "tbody",
            null,
            resources.map(function (resource) {
              return React.createElement(
                "tr",
                { "ng-repeat": "true" },
                React.createElement(
                  "td",
                  { className: "dont-break-out" },
                  resource.id
                ),
                React.createElement(
                  "td",
                  null,
                  resource.revision
                ),
                React.createElement(
                  "td",
                  null,
                  resource.modified_date
                ),
                React.createElement(
                  "td",
                  null,
                  resource.modified_by
                ),
                React.createElement(
                  "td",
                  null,
                  React.createElement("span", { className: "glyphicon glyphicon-menu-right" })
                )
              );
            })
          )
        );
      }
    }
  }]);

  return ServicesList;
}(React.Component);

ReactDOM.render(React.createElement(ServicesList, null), document.getElementById('like_button_container'));