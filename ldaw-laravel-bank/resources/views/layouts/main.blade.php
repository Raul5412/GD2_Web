<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
        <title>
            @hasSection('title')
                @yield('title') - Super Bank
            @else
                Super Bank
            @endif
        </title>
        <link rel="stylesheet" href="https://unpkg.com/@coreui/coreui@3.4.0/dist/css/coreui.min.css">
        <link rel="stylesheet" href="https://unpkg.com/@coreui/icons@2.0.0-beta.3/css/all.min.css">
        <meta name="robots" content="noindex">
        @stack('layout_before_end_head')
    </head>
    <body class="c-app flex-row @yield('layout_body_class_append')">
        <div class="container">
            @yield('content')
        </div>
        <script src="https://unpkg.com/@coreui/coreui@3.4.0/dist/js/coreui.bundle.min.js"></script>
        @stack('layout_before_end_body')
    </body>
</html>
