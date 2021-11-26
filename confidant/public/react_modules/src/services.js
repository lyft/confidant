
'use strict';


class Resources extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      resourceType: 'credentials' ,
      searchText: ''
    };
  }
  
  searchFilter = (searchText) => {
    console.log('searching...' + searchText)
    this.setState(
      { 
        searchText: searchText,
      }
    )
    console.log(this.state)
  }

  toggleType = (resourceType) => {
    console.log('filtering...' + resourceType)
    this.setState(
      { 
        resourceType: resourceType,
      }
    )
    console.log(this.state)
  }
  
  render() {
      return (
        <div>
          <SearchFilter onSearch={this.searchFilter}/>
          <Buttons onClickity={this.toggleType} />
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

class SearchFilter extends React.Component {
  constructor(props) {
    super(props);
    this.state = {value: ''}
    this.handleChange = this.handleChange.bind(this);
  }

  handleChange(event) {
    this.setState({value: event.target.value});
    this.props.onSearch(event.target.value)
  }

  render() {
      return (
        <input 
            type="search"
            className="form-control"
            value={this.state.value}
            onChange={this.handleChange}
            placeholder="filter (credential, blind-credential, or service name)"
        />
      );
  }
}

class Buttons extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
        buttons: [['credentials', 'Credentials'], ['blind_credentials', 'Blind Credentials'], ['services', 'Services']],
        activeIndex: 0
    }
  }

  filterme = (resourceType, index) => {
    console.log(resourceType)
    this.setState({activeIndex: index})
    this.props.onClickity(resourceType)
  }
  
  render() {
      const {buttons, activeIndex} = this.state;
      return (
        <div className="col-md-9">
          {buttons.map((type, i) => (
             <button 
                key={type[0]}
                type="button" 
                className={i == activeIndex ? "btn active": "btn"}
                onClick={()=>this.filterme(type[0], i)}>
              {type[1]}  
             </button>
          ))}
        </div>
      );
  }
}

class ServicesList extends React.Component {
  constructor(props) {
    super(props);
    this.state = {};
  }

  componentDidMount() {
    fetch("/v1/services")
      .then(res => res.json())
      .then(
        (result) => {
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
  
  searchFilter = (searchTxt, resources) => {
    let re = new RegExp(searchTxt, "g");
    let res = resources.filter(resource => re.test(resource.id))
    return res
  }
  
  render() {
    let { error, isLoaded, resources } = this.state;
    if (error) {
      return (<div>Error: {error.message}</div>);
    } else if (!isLoaded) {
      return <tr><td>Loading...</td></tr>;
    } else {
      resources = this.searchFilter(this.props.filter.searchText, resources)
      return (
        resources.map(resource => (
        <tr key={ resource.id } style={{cursor: "pointer"}} className={ this.props.filter.resourceType != "services"? "ng-hide":""}>
          <td>{ resource.id }</td>
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
    this.state = {};
  }

  componentDidMount() {
    fetch("/v1/credentials")
      .then(res => res.json())
      .then(
        (result) => {
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

  searchFilter = (searchTxt, resources) => {
    let re = new RegExp(searchTxt, "g");
    let res = resources.filter(resource => re.test(resource.name))
    return res
  }

  render() {
    let { error, isLoaded, resources } = this.state;
    if (error) {
      return (<div>Error: {error.message}</div>);
    } else if (!isLoaded) {
      return <tr><td>Loading...</td></tr>;
    } else {
      resources = this.searchFilter(this.props.filter.searchText, resources)
      return (
        resources.map(resource => (
          <tr key={ resource.id } onClick={() => console.log('clicked') } style={{cursor: "pointer"}} className={ this.props.filter.resourceType!="credentials"? "ng-hide":""}>
            <td>{ resource.name }</td>
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
