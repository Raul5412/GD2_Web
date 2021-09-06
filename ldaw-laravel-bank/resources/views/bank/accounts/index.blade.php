@extends('layouts.bank')

@section('content')
<div class="row">
    <div class="col-lg-12">
        <div class="card">
            <div class="card-header">
                Cuentas
                <div class="card-header-actions">
                    <a class="card-header-action" href="{{ route('bank.accounts.create') }}">
                        <i class="c-icon cil-plus"></i>
                    </a>
                </div>
            </div>
            <div class="card-body">
                <table class="table table-responsive-sm table-bordered">
                    <thead>
                        <tr>
                            <th>Número de cuenta</th>
                            <th>Cuenta</th>
                            <th>Balance</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($accounts as $account)
                            <tr>
                                <td>{{ $account->account_number }}</td>
                                <td>{{ $account->name }}</td>
                                <td>
                                    @money($account->decimal_current_balance)
                                </td>
                                <td>
                                    <a
                                        class="btn btn-sm btn-outline-primary"
                                        href="{{ route('bank.accounts-movements.create', compact('account'))}}">
                                        Registrar movimiento
                                    </a>
                                    <a
                                        class="btn btn-sm btn-outline-primary"
                                        href="{{ route('bank.accounts-movements.index', compact('account'))}}">
                                        Historial de movimientos
                                    </a>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
@endsection
