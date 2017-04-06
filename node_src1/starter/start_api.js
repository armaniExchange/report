

import ReportApi from '../src/reportApi';

const reportApi = new ReportApi();
// reportApi.report({
//   db: 'basic',
//   total_connection: true
// }, (records) => {
//   console.log('Records', records);
// });

reportApi.report({
  db: 'basic',
  total_connection: true
}).then((records) => {
  // console.log(records);
  console.log(records.length);
});

// reportApi.reportObj((records) => {
//   console.log(records);
// });

reportApi.reportObj().then((records) => {
  console.log(records);
});
