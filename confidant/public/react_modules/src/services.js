
const Link = ReactRouterDOM.Link

let { BrowserRouter, Switch, Redirect, Router } = ReactRouterDOM;
let { useHistory, useLocation } = ReactRouterDOM;
let {useEffect, useState} = React

const AppWrapper = () => {
  return (
      <BrowserRouter forceRefresh={true}>
        <Resources />
      </BrowserRouter>
  );
};

const Resources = (props) => {
  const [resourceType, setResourceType] = useState('credentials');
  const [searchText, setSearchText] = useState('')
  const [showDisabled, setShowDisabled] = useState(false)
    
  const searchFilter = (searchText) => {
    setSearchText(searchText)
  }

  const toggleDisableResources = () => {
    setShowDisabled(!showDisabled)
  }

  const toggleType = (resourceType) => {
    setResourceType(resourceType)
  }
  
  return (
    <div>
      <div className="row">
        <div className="form-group col-md-12">
          <SearchFilter onSearch={searchFilter}/>
        </div>
      </div>
      <div className="row has-margin-bottom-lg">
        <div className="col-md-9">
          <DisableEnableCheckBox checked={showDisabled} onClickity={toggleDisableResources} />
          <Buttons onClickity={toggleType} />
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
          <ResourcesList resourceType='services' filterSearchText={searchText} filterResourceType={resourceType} filterDisabled={showDisabled} />
          <ResourcesList resourceType='credentials' filterSearchText={searchText} filterResourceType={resourceType} filterDisabled={showDisabled} />
        </tbody>
      </table>
    </div>
  );

}

function DisableEnableCheckBox(props) {
  return (
    <label>
      <input type="checkbox" checked={props.checked} onChange={() => props.onClickity()} /> disabled resources
    </label>
  );
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

function Buttons(props)  {

  const [buttons, setButtons] = useState([['credentials', 'Credentials'], ['blind_credentials', 'Blind Credentials'], ['services', 'Services']])
  const [activeIndex, setActiveIndex] = useState(0)

  const filterme = (resourceType, index) => {
    console.log(resourceType)
    setActiveIndex(index)
    props.onClickity(resourceType)
  }
  return (
      buttons.map((type, i) => (
          <button 
            key={type[0]}
            type="button" 
            className={i == activeIndex ? "btn active": "btn"}
            onClick={()=>filterme(type[0], i)}>
          {type[1]}  
          </button>
      ))
  );
}

function ResourcesList(props) {

  const [resources, setResources] = useState();
  const [isLoaded, setIsLoaded] = useState(false);
  const [error, setError] = useState();
  const resourceType = (props.resourceType == 'credentials') ? 'credentials' : 'services';
  let history = useHistory();

  useEffect(() =>  {
    console.log(props.filterResourceType)
    fetch(`/v1/${resourceType}`)
      .then(res => res.json())
      .then(
        (result) => {
          if (resourceType == 'credentials') {
            setResources(result.credentials);
          }
          else {
            setResources(result.services);
          }
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

  let filterResources = (searchTxt, showDisabled, resources) => {
    let re = new RegExp(searchTxt);
    let filtered = []
    if (resourceType == 'credentials') {
      filtered = resources.filter(resource => re.test(resource.name) && (!resource.enabled == showDisabled || resource.enabled ))
    }
    else {
      filtered = resources.filter(resource => re.test(resource.id) && (!resource.enabled == showDisabled || resource.enabled ))
    }
    return filtered
  }

  if(!isLoaded) return <tr><td>Loading...</td></tr>;
  if(error) return (<div>Error: {error.message}</div>); 
  return (
      filterResources(props.filterSearchText, props.filterDisabled, resources).map(resource => (
        <tr key={ resource.id }
            onClick={ () => history.push(`#/resources/${resourceType}/${resource.id}`) }
            style={{cursor: "pointer"}}
            className={ props.filterResourceType!=resourceType? "ng-hide":""}>
          <td>{ resourceType=='credentials'? resource.name : resource.id }</td>
          <td>{ resource.revision }</td>
          <td>{ resource.modified_date }</td>
          <td>{ resource.modified_by }</td>
          <td><span className="glyphicon glyphicon-menu-right"></span></td>
        </tr>
      )
    )
  );
}

export default AppWrapper
