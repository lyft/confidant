'use strict';

const e = React.createElement;

class ServicesList extends React.Component {
  constructor(props) {
    super(props);
    this.state = { liked: false };
  }

  componentDidMount() {
    fetch("/v1/services")
      .then(res => res.json())
      .then(
        (result) => {
          console.log(result.services)
          this.setState({
            isLoaded: true,
            resources: result.services
          });
        },
        // Note: it's important to handle errors here
        // instead of a catch() block so that we don't swallow
        // exceptions from actual bugs in components.
        (error) => {
          this.setState({
            isLoaded: true,
            error
          });
        }
      )
  }

  render() {
    const { error, isLoaded, resources } = this.state;
    if (error) {
      return (<div>Error: {error.message}</div>);
    } else if (!isLoaded) {
      return <div>Loading...</div>;
    } else {
      return (
        <table className="table table-hover">
          <tbody>
            {resources.map(resource => (
            <tr ng-repeat="true">
                <td className="dont-break-out">{ resource.id }</td>
                <td>{ resource.revision }</td>
                <td>{ resource.modified_date }</td>
                <td>{ resource.modified_by }</td>
                <td><span className="glyphicon glyphicon-menu-right"></span></td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
  }
}

ReactDOM.render(<ServicesList />, document.getElementById('like_button_container'));   
