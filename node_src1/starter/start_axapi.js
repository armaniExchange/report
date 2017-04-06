
import AxapiRequest from '../src/axapiRequest';

const request = new AxapiRequest();

request.get('obj-stats-id/2015/schema').then((result) => {
  console.log(result);
});
