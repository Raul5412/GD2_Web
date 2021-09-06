@extends('layouts.bank')

@section('content')
<div class="row">
    <div class="col-lg-12">
        <div class="card">
            <form method="POST" action="{{ route('bank.accounts.store') }}">
                @csrf
                <div class="card-header">
                    Crear nueva cuenta
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label for="account-name">
                            Nombre <span class="text-danger font-weight-bold">*</span>
                        </label>
                        <input class="form-control" id="account-name" type="text" name="name">
                    </div>
                </div>
                <div class="card-footer">
                    <button class="btn btn-sm btn-primary" type="submit">Crear</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection
