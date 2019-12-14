// Generated on 2014-11-03 using generator-angular 0.9.8
'use strict';

module.exports = function (grunt) {

  // Load grunt tasks automatically
  require('load-grunt-tasks')(grunt);

  // Time how long tasks take. Can help when optimizing build times
  require('time-grunt')(grunt);

  // Configurable paths for the application
  var appConfig = {
    nodeDir: 'node_modules',
    app: 'confidant/public',
    components: 'confidant/public/components',
    dist: 'confidant/dist'
  };

  // Define the configuration for all the tasks
  grunt.initConfig({

    // Project settings
    project: appConfig,

    // Watches files for changes and runs tasks based on the changed files
    watch: {
      js: {
        files: ['<%= project.app %>/modules/**/*.js'],
        tasks: ['newer:jshint:all']
      },
      jsTest: {
        files: ['<%= project.app %>/modules/**/*.js'],
        tasks: ['test']
      },
      styles: {
        files: ['<%= project.app %>/styles/**/*.css'],
        tasks: ['newer:copy:styles']
      },
      gruntfile: {
        files: ['Gruntfile.js']
      }
    },

    // Make sure code styles are up to par and there are no obvious mistakes
    jshint: {
      options: {
        jshintrc: '.jshintrc',
        reporter: require('jshint-stylish')
      },
      all: {
        src: [
          'Gruntfile.js',
          '<%= project.app %>/modules/**/*.js'
        ]
      },
      test: {
        options: {
          jshintrc: 'test/.jshintrc'
        },
        src: ['test/spec/**/*.js']
      }
    },

    // Automatically inject app components
    injector: {
      options: {
        ignorePath: '<%= project.app %>',
        relative: false,
        destFile:'<%= project.app %>/index.html'
      },
      scripts: {
        src: [
            '<%= project.components %>/lodash/lodash.js',
            '<%= project.components %>/jquery/dist/jquery.js',
            '<%= project.components %>/angular/angular.js',
            '<%= project.components %>/bootstrap/dist/js/bootstrap.js',
            '<%= project.components %>/angular-resource/angular-resource.js',
            '<%= project.components %>/angular-cookies/angular-cookies.js',
            '<%= project.components %>/angular-sanitize/angular-sanitize.js',
            '<%= project.components %>/angular-animate/angular-animate.js',
            '<%= project.components %>/angular-touch/angular-touch.js',
            '<%= project.components %>/angular-route/angular-route.js',
            '<%= project.components %>/angular-ui-bootstrap/ui-bootstrap-tpls.js',
            '<%= project.components %>/angular-xeditable/dist/js/xeditable.js',
            '<%= project.components %>/@uirouter/angularjs/release/angular-ui-router.js',
            '<%= project.components %>/spin.js/spin.js',
            '<%= project.app %>/js/**/*.js',
            '<%= project.app %>/modules/**/*.js'
        ]
      },
      styles: {
        src: [
            '<%= project.components %>/bootstrap/dist/css/bootstrap.css',
            '<%= project.components %>/angular-xeditable/dist/css/xeditable.css',
            '<%= project.components %>/angular/angular-csp.css',
            '<%= project.app %>/styles/**/*.css',
            '<%= project.app %>/angular/angular-csp.css'
        ]
      }
    },

    // Renames files for browser caching purposes
    filerev: {
      dist: {
        src: [
          '<%= project.dist %>/scripts/**/*.js',
          '<%= project.dist %>/styles/**/*.css',
          '<%= project.dist %>/images/**/*.{png,jpg,jpeg,gif,webp,svg}',
          '<%= project.dist %>/styles/fonts/*'
        ]
      }
    },

    /* jshint -W106 */
    filerev_replace: {
      dist: {
        options: {
          assets_root: '<%= project.dist %>'
        },
        src: [
          '<%= project.dist %>/index.html',
          '<%= project.dist %>/styles/**/*.css',
          '<%= project.dist %>/scripts/**/*.js'
        ]
      }
    },
    /* jshint +W106 */

    // Reads HTML for usemin blocks to enable smart builds that automatically
    // concat, minify and revision files. Creates configurations in memory so
    // additional tasks can operate on them
    useminPrepare: {
      html: '<%= project.app %>/index.html',
      options: {
        dest: '<%= project.dist %>',
        flow: {
          html: {
            steps: {
              js: ['concat', 'uglifyjs'],
              css: ['cssmin']
            },
            post: {}
          }
        }
      }
    },

    // Performs rewrites based on filerev and the useminPrepare configuration
    usemin: {
      html: ['<%= project.dist %>/**/*.html'],
      css: ['<%= project.dist %>/styles/**/*.css'],
      options: {
        assetsDirs: ['<%= project.dist %>','<%= project.dist %>/images']
      }
    },

    htmlmin: {
      dist: {
        options: {
          collapseWhitespace: true,
          conservativeCollapse: true,
          collapseBooleanAttributes: true,
          removeCommentsFromCDATA: true,
          removeOptionalTags: true
        },
        files: [{
          expand: true,
          cwd: '<%= project.dist %>',
          src: ['*.html'],
          dest: '<%= project.dist %>'
        }]
      }
    },

    // ng-annotate tries to make the code safe for minification automatically
    // by using the Angular long form for dependency injection.
    ngAnnotate: {
      dist: {
        files: [{
          expand: true,
          cwd: '.tmp/concat/scripts',
          src: ['*.js', '!oldieshim.js'],
          dest: '.tmp/concat/scripts'
        }]
      }
    },

    // Copies remaining files to places other tasks can use
    copy: {
      components: {
        files: [
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['jquery/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['json3/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['es5-shim/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['bootstrap/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-resource/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-cookies/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-sanitize/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-animate/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-touch/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-route/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-ui-bootstrap/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['angular-xeditable/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['\@uirouter/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['lodash/**']},
          {expand: true, cwd: '<%= project.nodeDir %>', dest: '<%= project.components %>/', src: ['spin.js/**']}
        ]
      },
      dist: {
        files: [{
          expand: true,
          dot: true,
          cwd: '<%= project.app %>',
          dest: '<%= project.dist %>',
          src: [
            '*.{ico,png,txt}',
            '**/*.html',
            'images/**/*.{webp}',
            'fonts/*'
          ]
        }, {
          expand: true,
          cwd: '.tmp/images',
          dest: '<%= project.dist %>/images',
          src: ['generated/*']
        }, {
          expand: true,
          cwd: '<%= project.components %>/bootstrap/dist',
          src: 'fonts/*',
          dest: '<%= project.dist %>'
        }]
      },
      styles: {
        files: [{
          expand: true,
          cwd: '<%= project.app %>/styles',
          dest: '.tmp/styles/',
          src:  '**/*.css'
        }, {
          expand: true,
          cwd: '<%= project.app %>',
          dest: '<%= project.dist %>',
          src: 'angular/angular-csp.css'
        }]
      }
    },

    // Run some tasks in parallel to speed up the build process
    concurrent: {
      server: [
        'copy:styles'
      ],
      test: [
        'copy:styles'
      ],
      dist: [
        'copy:styles'
      ]
    },

    clean: {
        components: ['<%= project.components %>'],
        dist: ['<%= project.dist %>']
    },

  });

  grunt.registerTask('test', [
    'newer:jshint:all'
  ]);

  grunt.registerTask('testci', [
    'newer:jshint:all'
  ]);

  grunt.registerTask('build', [
    'clean:dist',
    'clean:components',
    'copy:components',
    'injector',
    'useminPrepare',
    'concurrent:dist',
    'concat',
    'ngAnnotate',
    'copy:dist',
    'cssmin',
    'uglify',
    'filerev',
    'filerev_replace:dist',
    'usemin',
    'htmlmin'
  ]);

  grunt.registerTask('default', [
    'newer:jshint'
  ]);
};
