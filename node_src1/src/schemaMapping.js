import AxapiRequest from './axapiRequest';
import _ from 'lodash';

class SchemaMapping{
  
  constructor() {
    this.request = new AxapiRequest();
  }

  get(objStatsId) {
    const self = this;
    return new Promise((resolve, reject) => {
      if (!objStatsId) {
        reject();
        return;
      }

      self.request.get(`obj-stats-id/${objStatsId}/schema`).then((result) => {
        const properties = _.get(result, ['properties', 'stats', 'properties']);
        if (!properties) {
          reject(); return;
        }

        let mapping = {};
        _.forEach(properties, (options, key) => {
          mapping[_.words(key)] = options.oid;
        });
        resolve(mapping);
      });
    });
    
  }
}

export default SchemaMapping;
