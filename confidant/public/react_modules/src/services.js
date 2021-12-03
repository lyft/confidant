

const Link = ReactRouterDOM.Link

// let { BrowserRouter, Switch, Redirect, Route } = ReactRouterDOM;
let { BrowserRouter, Switch, Redirect, Router } = ReactRouterDOM;
let { useHistory, useLocation } = ReactRouterDOM;
let {useEffect, useState} = React
{/* <Resources /> */}
const AppWrapper = () => {
  return (
      <BrowserRouter forceRefresh={true}>
        <Resources />
      </BrowserRouter>
  );
};

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
          <div className="row">
            <div className="form-group col-md-12">
              <SearchFilter onSearch={this.searchFilter}/>
            </div>
          </div>
          <div className="row has-margin-bottom-lg">
            <div className="col-md-9">
              <Buttons onClickity={this.toggleType} />
            </div>
            {/* <div className="btn-group dropdown col-md-3">
              <button type="button" className="btn dropdown-toggle call-to-action" data-toggle="dropdown" aria-expanded="false">Create <span className="glyphicon glyphicon-chevron-down glyphicon-xs"></span></button>
              <ul className="dropdown-menu" role="menu">
                <li ng-show="globalPermissions.credentials.create"><a href="#/resources/new/credential">Create credential</a></li>
                <li ng-show="globalPermissions.services.create"><a href="#/resources/new/service">Create service</a></li>
              </ul>
            </div> */}
          </div>

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

function SearchFilter(props) {
  const [value, setValue] = useState('');

  const handleChange = (event) => {
    setValue(event.target.value)
    props.onSearch(event.target.value)
  }

  return (
    <input 
        type="search"
        className="form-control"
        value={value}
        onChange={handleChange}
        placeholder="filter (credential, blind-credential, or service name)"
    />
  );
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
          buttons.map((type, i) => (
             <button 
                key={type[0]}
                type="button" 
                className={i == activeIndex ? "btn active": "btn"}
                onClick={()=>this.filterme(type[0], i)}>
              {type[1]}  
             </button>
          ))
      );
  }
}

function ServicesList(props) {

  const [resources, setResources] = useState();
  const [isLoaded, setIsLoaded] = useState(false);
  const [error, setError] = useState();
  let history = useHistory();

  useEffect(() =>  {
    fetch("/v1/services")
      .then(res => res.json())
      .then(
        (result) => {
          setResources(result.services);
          setIsLoaded(true);
        },
        // Note: it's important to handle errors here
        // instead of a catch() block so that we don't swallow
        // exceptions from actual bugs in components.
        (error) => {
          setIsLoaded(true);
          setError(error);
        }
      )
  }, [])

  const searchFilter = (searchTxt, resources) => {
    let re = new RegExp(searchTxt, "g");
    let res = resources.filter(resource => re.test(resource.name))
    return res
  }

  if(!isLoaded) return <tr><td>Loading...</td></tr>;
  if(error) return (<div>Error: {error.message}</div>); 
  return (
    searchFilter(props.filter.searchText, resources).map(resource => (
        <tr key={ resource.id }
            onClick={ () => history.push(`#/resources/services/${resource.id}`) }
            style={{cursor: "pointer"}}
            className={ props.filter.resourceType!="services"? "ng-hide":""}>
          <td>{ resource.id }</td>
          <td>{ resource.revision }</td>
          <td>{ resource.modified_date }</td>
          <td>{ resource.modified_by }</td>
          <td><span className="glyphicon glyphicon-menu-right"></span></td>
        </tr>
      )
    )
  );
}



function CredentialsList(props) {

  const [resources, setResources] = useState();
  const [isLoaded, setIsLoaded] = useState(false);
  const [error, setError] = useState();
  let history = useHistory();

  useEffect(() =>  {
    fetch("/v1/credentials")
      .then(res => res.json())
      .then(
        (result) => {
          setResources(result.credentials);
          setIsLoaded(true);
        },
        // Note: it's important to handle errors here
        // instead of a catch() block so that we don't swallow
        // exceptions from actual bugs in components.
        (error) => {
          setIsLoaded(true);
          setError(error);
        }
      )
  }, [])

  const searchFilter = (searchTxt, resources) => {
    let re = new RegExp(searchTxt, "g");
    let res = resources.filter(resource => re.test(resource.name))
    console.log(searchTxt)
    console.log(resources)
    return res
  }

  if(!isLoaded) return <tr><td>Loading...</td></tr>;
  if(error) return (<div>Error: {error.message}</div>); 
  return (
      searchFilter(props.filter.searchText, resources).map(resource => (
        <tr key={ resource.id }
            onClick={ () => history.push(`#/resources/credentials/${resource.id}`) }
            style={{cursor: "pointer"}}
            className={ props.filter.resourceType!="credentials"? "ng-hide":""}>
          <td>{ resource.name }</td>
          <td>{ resource.revision }</td>
          <td>{ resource.modified_date }</td>
          <td>{ resource.modified_by }</td>
          <td><span className="glyphicon glyphicon-menu-right"></span></td>
        </tr>
      )
    )
  );
}

function ButtonTest() {
  console.log('test!!')
  let history = useHistory();
  // debugger
  console.log(history)
  const handleOnClick = () => {
    history.push('/#/resources/credentials/9d49d735c5a84510a332b8c929d3d265');
  }
  return (
    <button type="button" onClick={handleOnClick}>
      Go home
    </button>
  );
}

function waitForElm(selector) {
  return new Promise(resolve => {
      if (document.querySelector(selector)) {
          return resolve(document.querySelector(selector));
      }

      const observer = new MutationObserver(mutations => {
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

export default AppWrapper
