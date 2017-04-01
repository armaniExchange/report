
import KnowLevel from './knowLevel';
import _ from 'lodash';

class Report {

  constructor() {
    this.recordKnowLevel = new KnowLevel('record');
    this.record5KnowLevel = new KnowLevel('record5');
    this.record10KnowLevel = new KnowLevel('record10');
  }

  getKey(oid, uuid, timestamps) {
    return `.time.${oid}.${uuid}.${timestamps}`;  
  }

  getFirstData(knowLevel, oid, uuid, callback) {
    const start = `.time.${oid}.${uuid}.0`;
    const options = {
      keys: true,
      values: true,
      start: start,
      limit: 1
    }

    knowLevel.find(options, callback);
  }

  getInitialData(knowLevel, oid, uuid, startime, callback) {
    const start = `.time.${oid}.${uuid}.${startime}`;
    const options = {
      keys: true,
      values: true,
      gt: start,
      limit: 5
    }

    knowLevel.find(options, callback);
  }

  getLastNData(knowLevel, oid, uuid, limit, callback) {
    const end = `.time.${oid}.${uuid}.9`;
    const options = {
      keys: true,
      values: true,
      lt: end,
      limit: limit
    }

    knowLevel.find(options, callback);
  }
  getLastData(knowLevel, oid, uuid, callback) {
    const end = `.time.${oid}.${uuid}.9`;
    const options = {
      keys: true,
      values: true,
      lt: end,
      reverse: true,
      limit: 1
    };

    knowLevel.find(options, callback);
  }

  reduce(oid, uuid) {
    const self = this;

    self.getLastData(self.record5KnowLevel, oid, uuid, (data) => {
      let startime = 0;
      if (data && data.length > 0) {
        const lastItem = data[0];
        startime = lastItem.timestamps;
      }

      self.start(oid, uuid, startime);
    });
  }

  start(oid, uuid, startime) {
    const self = this;
    self.getInitialData(self.recordKnowLevel, oid, uuid, startime, (data) => {
      if (data && data.length === 5) {
        self.saveNewRecord(oid, uuid, self.record5KnowLevel, data, () => {
          const newStartime = data[4].timestamps;
          self.start(oid, uuid, newStartime);
        });
      }
    });
  }

  // reduce(oid, uuid) {
  //   const self = this;
  //   this.getLastNData(this.recordKnowLevel, oid, uuid, 5, (data) => {
  //     if (data.length === 5) {
  //       self.reduce5(oid, uuid, data);
  //     }
  //   });
  // }

  // reduce5(oid, uuid, recordData) {
  //   const self = this;
  //   self.getLastNData(this.record5KnowLevel, oid, uuid, 1, (data) => {
  //     console.log(data, data.length);
  //     if (data && data.length > 0) {
  //       const lastItem = data[0];
  //       console.log(recordData[0].timestamps, lastItem.timestamps);
  //       console.log(recordData[0].timestamps > lastItem.timestamps);
  //       if (recordData[0].timestamps > lastItem.timestamps) {
  //         self.saveNewRecord(oid, uuid, self.record5KnowLevel, recordData);          
  //       }
  //     } else {
  //       self.saveNewRecord(oid, uuid, self.record5KnowLevel, recordData);
  //     }
      
  //   });
  // }

  saveNewRecord(oid, uuid, knowLevel, recordData, callback) {
    const self = this;
    const averageRecord = self.average(recordData);
    const lastRecord = recordData[recordData.length - 1];
    const key = self.getKey(oid, uuid, lastRecord.timestamps);
    knowLevel.saveRecord(key, JSON.stringify(averageRecord), () => {
      self.record5KnowLevel.find({
        keys: true,
        values: true
      }, function(data) {
        console.log('Total react 5: ', data.length);
        callback();
      });
    });
  }

  average(data) {
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

  find(category, startime, endtime, callback) {
    if (!category) {
      callback({err: 'Unknow category!'});
      return;
    }

    startime = startime ? startime : new Date().getTime() - 100 * 1000;
    endtime = endtime ? endtime : new Date().getTime();

    // const start = `.${category}.${startime}`;
    // const end = `.${category}.${endtime}`;

    const start = '.time.2015.13f366fe-1699-11e7-b829-001fa001dd34.1491048879602';
    this.record5KnowLevel.find({
      keys: true, 
      values: true,
      limit: 20
    }, callback);

  }
}

export default Report;



// const report = new Report();

// report.reduce(2015, '13f366fe-1699-11e7-b829-001fa001dd34');
