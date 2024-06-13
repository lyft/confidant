import AppWrapper from './resources.js';
let { BrowserRouter, Switch, Redirect, Router } = ReactRouterDOM;
let {useEffect, useState} = React

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
  
// todo cleanup, move into 
waitForElm('#reactDiv').then((elm) => {
    console.log('Element is ready');
    console.log(elm.textContent);
    ReactDOM.render(<AppWrapper />, document.getElementById('reactDiv'))
});
  
const Header = (props) => {
    const [userEmail, setUserEmail] = useState();

    useEffect(() =>  {
        fetch(`v1/user/email`)
          .then(res => res.json())
          .then(
            (result) => {
                setUserEmail(result.email)
            },
            // Note: it's important to handle errors here
            // instead of a catch() block so that we don't swallow
            // exceptions from actual bugs in components.
            (error) => {

            }
          )
      }, [])

    return (
        <div>
            <div id="loading-spinner" loading-spinner="data-loading"></div>
            <header id="page-header" className="header">
                <nav id="site-navigation">
                <div className="container-fluid">
                    <p className="navbar-text pull-right"
                        style={{textAlign: "right"}}
                    >
                    Logged in as {userEmail} | <a href="loggedout">Log Out <span className="glyphicon glyphicon-log-out"></span></a>
                    </p>
                    <h1><a href="#"><img className="site-logo visible-sm visible-md visible-lg" src="images/logo.svg"/></a></h1>
                </div>
                </nav>
            </header>
        </div>
    )
}

const Navigation = (props) => {
    const [activeIndex, setActiveIndex] = useState(0)
    return (
        <div>
            <ul className="nav nav-pills has-margin-bottom">
                <li role="presentation" className={activeIndex == 0 ? "active": ""} ><a href="#/resources" onClick={()=>setActiveIndex(0)}>Resources <span className="glyphicon glyphicon-lock"></span></a></li>
                <li role="presentation" className={activeIndex == 1 ? "active": ""}><a href="#/history" onClick={()=>setActiveIndex(1)}>History <span className="glyphicon glyphicon-time"></span></a></li>
            </ul>
        </div>
    )
}

const Wrap = () => {
    return (
        <BrowserRouter forceRefresh={true}>
          <Header />
          <Navigation />
        </BrowserRouter>
    );
  };

ReactDOM.render(<Wrap />, document.getElementById('mainReactDiv'))