
import KnowLevel from './knowLevel';
import Faker from './faker';


const knowLevel = new KnowLevel('record');
const faker = new Faker();

// faker.repeat(10, (key, value) => {
//   knowLevel.saveRecord(key, JSON.stringify(value));
// });

// faker.repeatData((key, value) => {
//   knowLevel.saveRecord(JSON.stringify(key), JSON.stringify(value));
// });

// knowLevel.findRecord('.time.0.category.2015.a5125672-160d-11e7-9ba1-001fa001dd34.1491019995', (value) => {
//   console.log(value);
// });

// knowLevel.find({
//   keys: true, 
//   values: true,
//   end: '.time.2015.13f366fe-1699-11e7-b829-001fa001dd34.9'
// });

// var parse = require('json-literal-parse');
// var xs = parse('["robot",/^b[eo]{2}p$/,{"x":null,"y":0777}]');
// console.dir(xs);

// import JSONStream from 'JSONStream';

// knowLevel.queryRecord('map=[["username","location"]]');


function multiRecords() {
  function load() {
    const oid = 2015;
    const uuid = '13f366fe-1699-11e7-b829-001fa001dd34';
    const key = `.time.${oid}.${uuid}.${new Date().getTime()}`;
    console.log(key);
    knowLevel.saveRecord(key, JSON.stringify(faker.record()));
    setTimeout(load, 1000);
  }
  load();
}

function category() {
  const key = '.obj.2015.13f366fe-1699-11e7-b829-001fa001dd34';
  knowLevel.saveRecord(key, JSON.stringify({
    oid: 2015,
    uuid: '2015.13f366fe-1699-11e7-b829-001fa001dd34'
  }));
}

// category();

multiRecords();


