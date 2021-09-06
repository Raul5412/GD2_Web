@extends('layouts.bank')

@section('content')
<div class="row">
    <div class="col-lg-12">
        <div class="card">
            <div class="card-header">
                Cuenta: {{ $account->name }}
            </div>
            <div class="card-body">
                <table class="table table-responsive-sm table-bordered">
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>Tipo</th>
                            <th>Monto</th>
                            <th>Descripción</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($movements as $movement)
                            <tr>
                                <td>
                                    @datetime($movement->local_created_at)
                                </td>
                                <td>
                                    {{ $movement->readable_type }}
                                </td>
                                <td>
                                    @money($movement->decimal_amount)
                                </td>
                                <td>
                                    {{ $movement->description }}
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
