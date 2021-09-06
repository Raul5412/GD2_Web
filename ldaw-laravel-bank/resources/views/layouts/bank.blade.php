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
    <body class="c-app">
        <div class="c-sidebar c-sidebar-dark c-sidebar-fixed c-sidebar-lg-show" id="sidebar">
            <div class="c-sidebar-brand d-lg-down-none">
                Super bank
            </div>
            <ul class="c-sidebar-nav">
                <li class="c-sidebar-nav-item">
                    <a class="c-sidebar-nav-link" href="{{ route('bank.dashboard.index') }}">
                        <i class="c-sidebar-nav-icon cil-speedometer"></i>
                        Dashboard
                    </a>
                </li>
                <li class="c-sidebar-nav-item">
                    <a class="c-sidebar-nav-link" href="{{ route('bank.accounts.index') }}">
                        <i class="c-sidebar-nav-icon cil-puzzle"></i>
                        Cuentas
                    </a>
                </li>
            </ul>
            <button
                class="c-sidebar-minimizer c-class-toggler"
                type="button"
                data-target="_parent"
                data-class="c-sidebar-minimized"></button>
        </div>
        <div class="c-wrapper c-fixed-components">
            <header class="c-header c-header-light c-header-fixed c-header-with-subheader">
                <button
                    class="c-header-toggler c-class-toggler d-lg-none mfe-auto"
                    type="button"
                    data-target="#sidebar"
                    data-class="c-sidebar-show">
                    <i class="c-icon c-icon-lg cil-menu"></i>
                </button>
                <a class="c-header-brand d-lg-none" href="#">
                    <i class="cil-full"></i>
                </a>
                <button class="c-header-toggler c-class-toggler mfs-3 d-md-down-none" type="button" data-target="#sidebar" data-class="c-sidebar-lg-show" responsive="true">
                    <i class="cil-full"></i>
                </button>
                <ul class="c-header-nav ml-auto mr-4">
                    <li class="c-header-nav-item dropdown">
                        <a class="c-header-nav-link" data-toggle="dropdown" href="#" role="button"
                            aria-haspopup="true" aria-expanded="false">
                            <div class="c-avatar">
                                <img class="c-avatar-img" src="https://i.pravatar.cc/150" alt="">
                            </div>
                        </a>
                        <div class="dropdown-menu dropdown-menu-right pt-0">
                            <div class="dropdown-header bg-light py-2">
                                <strong>Cuenta</strong>
                            </div>
                            <a class="dropdown-item" href="{{ route('auth.logout') }}">
                                <i class="c-icon mfe-2 cil-user"></i> Cerrar sesión
                            </a>
                        </div>
                    </li>
                </ul>
            </header>
            <div class="c-body">
                <main class="c-main">
                    <div class="container-fluid">
                        @yield('content')
                    </div>
                </main>
            </div>
        </div>
        <script src="https://unpkg.com/@coreui/coreui@3.4.0/dist/js/coreui.bundle.min.js"></script>
        @stack('layout_before_end_body')
    </body>
</html>
