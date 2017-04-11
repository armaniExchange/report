
import ReportReduce from '../src/reportReduce';


const duration = 5 * 1000;
const reduce = () => {
  console.log(new Date(), 'Start reduce:');
  const report = new ReportReduce();
  report.on('over', () => {
    console.log(new Date(), 'End reduce, and registry next reduce.');
    setTimeout(reduce, duration);
  });
  report.reduce();
}

reduce();

