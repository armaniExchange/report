
import _ from 'lodash';
import KnowLevel from './knowLevel';

export function keyName(oid, uuid, timestamp) {
  return `.rpt.${uuid}.${timestamp}.${oid}`;
}

export function getKnowLevels(config) {
  let knowLevels = {};
  
  knowLevels['obj'] = new KnowLevel(config.objDB, 'obj');
  knowLevels['basic'] = new KnowLevel(config.rawDB);
  
  _.forEach(config.reducedDB, (value, key) => {
    knowLevels[key] = new KnowLevel(value.name);
  });
  return knowLevels;
}

export function getCurrentTimestamp() {
  return Math.round(new Date().getTime() / 1000);
}

export function average(data) {
    let total = {};
    data.map((item) => {
      _.forEach(item.data, (value, key) => {
        total[key] = total[key] ? total[key] : 0;
        total[key] += value;
      });
    });
    
    let result = {};
    let length = data.length;
    _.forEach(total, (value, key) => {
      result[key] = Math.round(total[key] / length);
    });
    return result;
  }

  export function zeroPoint(data) {
    let zeroData = {};
    _.forEach(data, (value, key) => {
      zeroData[key] = 0;
    });

    return zeroData;
  }


