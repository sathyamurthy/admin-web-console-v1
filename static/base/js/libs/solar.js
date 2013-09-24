(function(Backbone) {

  // Fixtures

	fixtures = [
	{"date_joined": "2013-08-05T01:55:49", "email": "sathya@ec.is", "first_name": "sathya", "groups": "/api/v1/groups/limit/3/", "id": 4, "is_active": true, "is_superuser": false, "last_login": "2013-08-05T01:55:49", "last_name": "", "username": "sathya"},
	{"date_joined": "2013-08-05T14:17:04", "email": "sathya@ec.is", "first_name": "sathyam", "groups": "/api/v1/groups/limit/4/", "id": 10, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:21:35", "last_name": "", "username": "sathyam"},
	{"date_joined": "2013-08-05T14:17:27", "email": "sathya@ec.is", "first_name": "Sathya murthy", "groups": "/api/v1/groups/limit/3/", "id": 11, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:27:47", "last_name": "Vellaichamy", "username": "satya"},
	{"date_joined": "2013-08-05T01:55:49", "email": "sathya@ec.is", "first_name": "sathya", "groups": "/api/v1/groups/limit/3/", "id": 1, "is_active": true, "is_superuser": false, "last_login": "2013-08-05T01:55:49", "last_name": "", "username": "sathya"},
	{"date_joined": "2013-08-05T14:17:04", "email": "sathya@ec.is", "first_name": "sathyam", "groups": "/api/v1/groups/limit/4/", "id": 2, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:21:35", "last_name": "", "username": "sathyam"},
	{"date_joined": "2013-08-05T14:17:27", "email": "sathya@ec.is", "first_name": "Sathya murthy", "groups": "/api/v1/groups/limit/3/", "id": 3, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:27:47", "last_name": "Vellaichamy", "username": "satya"},
	{"date_joined": "2013-08-05T01:55:49", "email": "sathya@ec.is", "first_name": "sathya", "groups": "/api/v1/groups/limit/3/", "id": 5, "is_active": true, "is_superuser": false, "last_login": "2013-08-05T01:55:49", "last_name": "", "username": "sathya"},
	{"date_joined": "2013-08-05T14:17:04", "email": "sathya@ec.is", "first_name": "sathyam", "groups": "/api/v1/groups/limit/4/", "id": 6, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:21:35", "last_name": "", "username": "sathyam"},
	{"date_joined": "2013-08-05T14:17:27", "email": "sathya@ec.is", "first_name": "Sathya murthy", "groups": "/api/v1/groups/limit/3/", "id": 7, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:27:47", "last_name": "Vellaichamy", "username": "satya"},
	{"date_joined": "2013-08-05T01:55:49", "email": "sathya@ec.is", "first_name": "sathya", "groups": "/api/v1/groups/limit/3/", "id": 8, "is_active": true, "is_superuser": false, "last_login": "2013-08-05T01:55:49", "last_name": "", "username": "sathya"},
	{"date_joined": "2013-08-05T14:17:04", "email": "sathya@ec.is", "first_name": "sathyam", "groups": "/api/v1/groups/limit/4/", "id": 9, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:21:35", "last_name": "", "username": "sathyam"},
	{"date_joined": "2013-08-05T14:17:27", "email": "sathya@ec.is", "first_name": "Sathya murthy", "groups": "/api/v1/groups/limit/3/", "id": 15, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:27:47", "last_name": "Vellaichamy", "username": "satya"},
	{"date_joined": "2013-08-05T01:55:49", "email": "sathya@ec.is", "first_name": "sathya", "groups": "/api/v1/groups/limit/3/", "id": 14, "is_active": true, "is_superuser": false, "last_login": "2013-08-05T01:55:49", "last_name": "", "username": "sathya"},
	{"date_joined": "2013-08-05T14:17:04", "email": "sathya@ec.is", "first_name": "sathyam", "groups": "/api/v1/groups/limit/4/", "id": 12, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:21:35", "last_name": "", "username": "sathyam"},
	{"date_joined": "2013-08-05T14:17:27", "email": "sathya@ec.is", "first_name": "Sathya murthy", "groups": "/api/v1/groups/limit/3/", "id": 13, "is_active": true, "is_superuser": false, "last_login": "2013-08-06T06:27:47", "last_name": "Vellaichamy", "username": "satya"}
	
	]

  var Planet = Backbone.Model.extend();

  var Planets = Backbone.Collection.extend({
    model: Planet
  });


  window.planets = new Planets();
  planets.reset(fixtures);


  window.datagrid2 = new Backbone.Datagrid({
    collection: planets,
    inMemory: true,
    paginated: true,
    footerControls: {
      left: Backbone.Datagrid.ItemsPerPage,
      middle: {
        control: Backbone.Datagrid.Pagination,
        full: true
      }
    },
    perPage: 10,
    rowClassName: function(planet) { return planet.get('name') === 'Mars' ? 'error' : ''; },
    /*columns: [{
      title: 'Le nom',
      property: 'name',
      header: true,
      sortable: true
    }*/

 	columns:[
 		{title: "Username","property": "username", header: true,sortable: true},
 		{title: "First name","property": "first_name", header: true,sortable: true},
 		{title: "Last name","property": "last_name", header: true,sortable: true},
 		{title: "Email","property": "email", header: true,sortable: true},
 		{title: "Active","property": "is_active", header: true,sortable: false},
 		{title: "Super user","property": "is_superuser", header: true,sortable: false},
 		{title: "Last login","property": "last_login", header: true,sortable: true},
 		{title: "Date joined","property": "date_joined", header: true,sortable: true},
 	
    {
      view: {
        type: Backbone.Datagrid.ActionCell,
        label: 'Edit',
        actionClassName: 'btn btn-primary',
        action: function(planet) {
          alert('Would edit ' + planet.get('id') + '!');
          return false;
        }
      }
    }]
  });

  datagrid2.render().$el.appendTo('#datagrid');

})(Backbone);
