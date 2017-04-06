
import request from 'request';

class AxapiRequest {

  constructor(token) {
    this.host = '192.168.105.88';
    this.token = token;
    this.options = {
      json:true,
      headers: {'Connection': 'close', 'Authorization': ''}
    }
  }

  

  axapiPromise (options) {
    return new Promise((resolve, reject) => {
      request(options, function(err, response, result) {
        if (err) {
          reject(new Error(err));
        }
        // console.log(response);
        if (!err && response.statusCode === 200) {
          resolve(result);
        } else {
          reject(new Error(err));
        }
      });
    });
  };

  async getAuthToken() {
    if (this.token) {
      return;
    }
    // let deviceInfo = this.getDeviceInfo(this.host);
    let deviceInfo = {username: 'admin', password: 'a10'};
    // console.log('=============== device info ==============', deviceInfo);
    let authOptions = Object.assign({}, this.options, {
      url: this.buildAXAPI('auth'),
      method: 'POST',
      body: {
        credentials:{username: deviceInfo['username'], password: deviceInfo['password']}
      }
    });

    let result =  await this.axapiPromise(authOptions);
    this.token = 'A10 ' + result.authresponse.signature;
  }

  buildAXAPI(path) {
    return 'http://' + this.host + '/axapi/v3/' + path;
  }

  async get(url) {
    await this.getAuthToken();
    this.options.headers['Authorization'] = this.token;
    let authOptions = Object.assign({}, this.options, {
      url: this.buildAXAPI(url),
      method: 'GET',
    });
    let result =  await this.axapiPromise(authOptions);
    return result;
  }
}

export default AxapiRequest;
