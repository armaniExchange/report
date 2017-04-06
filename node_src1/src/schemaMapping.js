import AxapiRequest from './axapiRequest';
import _ from 'lodash';

class SchemaMapping{
  
  constructor() {
    this.request = new AxapiRequest();
  }

  get(objStatsId) {
    return new Promise((resolve, reject) => {
      if (!objStatsId) {
        reject();
        return;
      }

      this.request.get(`obj-stats-id/${objStatsId}/schema`).then((result) => {
        const properties = _.get(result, ['properties', 'stats', 'properties']);
        if (!properties) {
          reject(); return;
        }

        let mapping = {};
        _.forEach(properties, (options, key) => {
          mapping[key] = options.oid;
        });
        resolve(mapping);
      });
    });
    
  }
}

export default SchemaMapping;
