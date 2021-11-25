'use strict';

const e = React.createElement;

class LikeButton extends React.Component {
  constructor(props) {
    super(props);
    this.state = { liked: false };
  }

  componentDidMount() {
    fetch("/v1/services")
      .then(res => res.json())
      .then(
        (result) => {
          console.log(result)
          this.setState({
            isLoaded: true,
            items: result.items
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

  // render() {
  //   if (this.state.liked) {
  //     return 'You liked this.';
  //   }
  //   return e(
  //     'button',
  //     { onClick: () => this.setState({ liked: true }) },
  //     'Like'
  //   );
  // }
  

//   render() {
//     const { error, isLoaded, items } = this.state;
//     if (error) {
//       return (<div>Error: {error.message}</div>);
//     } else if (!isLoaded) {
//       return <div>Loading...</div>;
//     } else {
//       return (
//         <ul>
//           {items.map(item => (
//             <li key={item.id}>
//               {item.name} {item.price}
//             </li>
//           ))}
//         </ul>
//       );
//     }
//   }

  // render() {
  //   if (this.state.liked) {
  //     return 'You liked this.';
  //   }
  //   return e(
  //     'button',
  //     { onClick: () => this.setState({ liked: true }) },
  //     'Like'
  //   );
  // }

}


// const domContainer = document.querySelector('#like_button_container');
// ReactDOM.render(e(LikeButton), domContainer);   
// ReactDOM.render(<LikeButton />, domContainer);   

ReactDOM.render(<LikeButton />, document.getElementById('like_button_container'));   
