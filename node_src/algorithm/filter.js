
const filters = {
  '2015': {
    objectId: '2015',
    description: 'Figure out total connection counter',
    collections: {
      total_connection: {
        description: 'Total Connection',
        operate: 'sum',
        from: ['ov_new_conn_l7', 'ov_new_conn_l4', 'ov_new_conn_ssl', 'ov_new_conn_ipnat']
      },
      avg_connection: {
        description: 'Average Connection',
        operate: 'avg',
        from: ['ov_new_conn_l7', 'ov_new_conn_l4', 'ov_new_conn_ssl', 'ov_new_conn_ipnat']
      }
    }
  }
};

export default filters;
