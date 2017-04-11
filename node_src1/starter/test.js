
// import KnowLevel from '../src/knowLevel';

// const knowLevel = new KnowLevel('raw_db', 'obj');

// knowLevel.find({
//   keys: true,
//   values: true
// }, (records) => {
//   console.log(records);
//   console.log(records.length);
// });

// const EventEmitter = require('events');

// const emitter = new EventEmitter();

// emitter.emit('test');
// emitter.emit('closed');


var tet = Object.assign({ keys: true, values: true }, 
{ keys: true,
  values: true,
  gt: '.rpt.9e2952fe-15de-11e7-81f6-001fa001dd34.1491895591670',
  lte: '.rpt.9e2952fe-15de-11e7-81f6-001fa001dd34.9',
  limit: 6 }
);

console.log(tet);