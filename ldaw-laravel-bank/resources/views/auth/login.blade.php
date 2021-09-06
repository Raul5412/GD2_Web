@extends('layouts.main')

@section('title')
    Inicio de sesión
@endsection

@section('layout_body_class_append')
align-items-center
@endsection

@section('content')
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card-group">
            <div class="card p-4">
                @if ($errors->any())
                    <div class="alert alert-danger">
                        <ul>
                            @foreach ($errors->all() as $error)
                                <li>{{ $error }}</li>
                            @endforeach
                        </ul>
                    </div>
                @endif
                <form method="post" action="{{ route('auth.login-user') }}">
                    @csrf
                    <div class="card-body">
                        <h1>Iniciar sesión</h1>
                        <p class="text-muted">
                            Inicia sesión en tu cuenta
                        </p>
                        <div class="input-group mb-3">
                            <div class="input-group-prepend">
                                <span class="input-group-text">
                                    <i class="cil-user"></i>
                                </span>
                            </div>
                            <input class="form-control" type="text" name="email" placeholder="Email">
                        </div>
                        <div class="input-group mb-4">
                            <div class="input-group-prepend">
                                <span class="input-group-text">
                                    <i class="cil-lock-locked"></i>
                                </span>
                            </div>
                            <input class="form-control" type="password" name="password" placeholder="Contraseña">
                        </div>
                        <div class="row">
                            <div class="col-6">
                                <button class="btn btn-primary px-4" type="submit">Iniciar sesión</button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="card text-white bg-primary py-5 d-md-down-none" style="width:44%">
                <div class="card-body text-center">
                    <div>
                        <h2>Registrate</h2>
                        <p>No olvides que puedes registrarte en el súper banco.</p>
                        <a class="btn btn-lg btn-outline-light mt-3" href="{{ route('auth.register') }}">
                            Registrate ahora
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
