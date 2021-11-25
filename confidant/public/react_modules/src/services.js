'use strict';

class Resources extends React.Component {
  constructor(props) {
    super(props);
    this.state = { resourceType: 'credentials' };
  }
  
  filter = resourceType => {
    console.log('filtering...' + resourceType)
    this.setState(
      { resourceType: resourceType}
    )
    console.log(this.state)
  }
  
  render() {
      return (
        <div>
          <Buttons onClickity={this.filter} />
          <table className="table table-hover">
            <thead>
              <tr>
                <th>Name</th>
                <th>Revision</th>
                <th>Modified</th>
                <th>Modified By</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <ServicesList filter={this.state}/>
              <CredentialsList filter={this.state}/>
            </tbody>
          </table>
        </div>
      );
  }
}

class Buttons extends React.Component {
  constructor(props) {
    super(props);
    this.state = { liked: false };
  }

  filterme = resourceType => {
    console.log(resourceType)
    this.props.onClickity(resourceType)
    // this.props.onClickity(event.target.value)
  }

  render() {
      return (
        <div className="col-md-9">
          <button type="button" className="btn" onClick={()=>this.filterme('credentials')} value='credentials'>Credentials</button>
          <button type="button" className="btn" onClick={()=>this.filterme('blind_credentials')} value='credentials' >Blind Credentials</button>
          <button type="button" className="btn" onClick={()=>this.filterme('services')} value='credentials'>Services</button>
        </div>
      );
  }
}

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
      return <tr><td>Loading...</td></tr>;
    } else {
      return (
        resources.map(resource => (
        <tr key={ resource.id } ng-repeat="true" className={ this.props.filter.resourceType=="credentials"? "ng-hide":""}>
          <td className="dont-break-out">{ resource.id }</td>
          <td>{ resource.revision }</td>
          <td>{ resource.modified_date }</td>
          <td>{ resource.modified_by }</td>
          <td><span className="glyphicon glyphicon-menu-right"></span></td>
        </tr>
        ))
      );
    }
  }
}

class CredentialsList extends React.Component {
  constructor(props) {
    super(props);
    this.state = { liked: false };
  }

  componentDidMount() {
    fetch("/v1/credentials")
      .then(res => res.json())
      .then(
        (result) => {
          console.log(result)
          this.setState({
            isLoaded: true,
            resources: result.credentials
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
      return <tr><td>Loading...</td></tr>;
    } else {
      return (
        resources.map(resource => (
        <tr key={ resource.id } ng-repeat="true">
          <td className="dont-break-out">{ resource.id }</td>
          <td>{ resource.revision }</td>
          <td>{ resource.modified_date }</td>
          <td>{ resource.modified_by }</td>
          <td><span className="glyphicon glyphicon-menu-right"></span></td>
        </tr>
        ))
      );
    }
  }
}

ReactDOM.render(<Resources />, document.getElementById('like_button_container'));   
