// Generated on 2014-11-03 using generator-angular 0.9.8
'use strict';

module.exports = function (grunt) {

  // Load grunt tasks automatically
  require('load-grunt-tasks')(grunt);

  grunt.loadNpmTasks('grunt-contrib-compass');

  // Time how long tasks take. Can help when optimizing build times
  require('time-grunt')(grunt);

  // Configurable paths for the application
  var appConfig = {
    app: require('./bower.json').appPath,
    dist: 'confidant/dist'
  };

  // Define the configuration for all the tasks
  grunt.initConfig({

    // Project settings
    project: appConfig,

    // Watches files for changes and runs tasks based on the changed files
    watch: {
      bower: {
        files: ['bower.json'],
        tasks: ['bower:install', 'wiredep', 'compass:app']
      },
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
      compass: {
        files: ['<%= project.app %>/{modules,styles}/**/*.{scss,sass}'],
        tasks: ['compass:app']
      },
      gruntfile: {
        files: ['Gruntfile.js']
      }
    },

    bower: {
      options: {
        targetDir: '<%= project.app %>/bower_components',
        copy: false
      },
      install: {
        options: {
          bowerOptions: {
            production: true
          }
        }
      }
    },

    compass: {
      options: {
        sassDir: '<%= project.app %>/styles',
        cssDir: '<%= project.app %>/styles',
        generatedImagesDir: '<%= project.app %>/images/generated',
        imagesDir: [
            '<%= project.app %>/images'
        ],
        javascriptsDir: '<%= project.app %>/scripts',
        fontsDir: '<%= project.app %>/styles/fonts',
        importPath: [
            '<%= project.app %>/bower_components',
            '<%= project.app %>/modules'
        ],
        httpImagesPath: '/images',
        httpGeneratedImagesPath: '/images/generated',
        httpFontsPath: '/styles/fonts',
        relativeAssets: true,
        assetCacheBuster: false,
        outputStyle: 'expanded',
        debugInfo: true
      },
      clean: {
        options: {
          debugInfo: false,
          clean: true
        }
      },
      app: {
        options: {
          outputStyle: 'expanded',
          debugInfo: true
        }
      },
      dist: {
        options: {
          cssDir: '<%= project.app %>/styles',
          generatedImagesDir: '<%= project.app %>/images/generated',
          outputStyle: 'compressed',
          debugInfo: false
        }
      },
      test: {
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

    // Automatically inject Bower components
    wiredep: {
      app: {
        src: ['<%= project.app %>/index.html'],
        ignorePath:  /\.\.\//,
        fileTypes: {
          html: {
            replace: {
              js: '<script src="/{{filePath}}"></script>'
            }
          }
        }
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
            '<%= project.app %>/js/**/*.js',
            '<%= project.app %>/modules/**/*.js'
        ]
      },
      styles: {
        src: ['<%= project.app %>/styles/**/*.css']
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

    // The following *-min tasks will produce minified files in the dist folder
    // By default, your `index.html`'s <!-- Usemin block --> will take care of
    // minification. These next options are pre-configured if you do not wish
    // to use the Usemin blocks.
    // cssmin: {
    //   dist: {
    //     files: {
    //       '<%= project.dist %>/styles/main.css': [
    //         '.tmp/styles/**/*.css'
    //       ]
    //     }
    //   }
    // },
    // uglify: {
    //   dist: {
    //     files: {
    //       '<%= project.dist %>/scripts/scripts.js': [
    //         '<%= project.dist %>/scripts/scripts.js'
    //       ]
    //     }
    //   }
    // },
    // concat: {
    //   dist: {}
    // },

    imagemin: {
     dist: {
       files: [{
         expand: true,
         cwd: '<%= project.app %>/images',
         src: '**/*.{png,jpg,jpeg,gif}',
         dest: '<%= project.dist %>/images'
       }]
     }
    },

    svgmin: {
      dist: {
        files: [{
          expand: true,
          cwd: '<%= project.app %>/images',
          src: '**/*.svg',
          dest: '<%= project.dist %>/images'
        }]
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

    // Replace Google CDN references
    cdnify: {
      dist: {
        html: ['<%= project.dist %>/*.html']
      }
    },

    // Copies remaining files to places other tasks can use
    copy: {
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
          cwd: '<%= project.app %>/bower_components/bootstrap/dist',
          src: 'fonts/*',
          dest: '<%= project.dist %>'
        }]
      },
      styles: {
        expand: true,
        cwd: '<%= project.app %>/styles',
        dest: '.tmp/styles/',
        src: '**/*.css'
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
        'copy:styles',
        'imagemin',
        'svgmin'
      ]
    },

    clean: {
        dist: ['<%= project.dist %>']
    },

    // Test settings
    karma: {
      unit: {
        configFile: 'test/karma.conf.js',
        singleRun: true
      },
      ci: {
        configFile: 'test/karma.conf.js',
        reporters: ['progress', 'junit'],
        singleRun: true
      }
    }
  });

  grunt.registerTask('test', [
    'newer:jshint:all',
    'karma:unit'
  ]);

  grunt.registerTask('testci', [
    'newer:jshint:all',
    'karma:ci'
  ]);

  grunt.registerTask('build', [
    'bower:install',
    'clean:dist',
    'compass:clean',
    'compass:app',
    'compass:dist',
    'wiredep',
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
    'newer:jshint',
    'test'
  ]);
};
