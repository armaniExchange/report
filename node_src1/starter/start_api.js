

import ReportApi from '../src/reportApi';

const reportApi = new ReportApi();
// reportApi.report({
//   db: 'basic',
//   total_connection: true
// }, (records) => {
//   console.log('Records', records);
// });

reportApi.report({
  db: '30m',
  uuid: '9e29b29e-15de-11e7-81f6-001fa001dd34',
  oid: '2015'
}).then((records) => {
  console.log(records);
  // console.log(records.length);
});

// reportApi.report({
//   db: 'basic',
//   uuid: '9e29b29e-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// reportApi.report({
//   db: 'basic',
//   uuid: '9e2a0802-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// reportApi.report({
//   db: 'basic',
//   uuid: '9e294f02-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// reportApi.report({
//   db: 'basic',
//   uuid: '9e294fde-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// reportApi.report({
//   db: 'basic',
//   uuid: '9e2950b0-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// reportApi.report({
//   db: 'basic',
//   uuid: '9e2952fe-15de-11e7-81f6-001fa001dd34',
//   total_connection: true
// }).then((records) => {
//   // console.log(records);
//   console.log(records.length);
// });

// // reportApi.reportObj((records) => {
// //   console.log(records);
// // });

// reportApi.reportObj().then((records) => {
//   console.log(records);
// });
