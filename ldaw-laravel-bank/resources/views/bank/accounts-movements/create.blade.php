@extends('layouts.bank')

@section('content')
<div class="row">
    <div class="col-lg-12">
        <div class="card">
            @if ($errors->any())
                <div class="alert alert-danger">
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif
            <form method="POST" action="{{ route('bank.accounts-movements.store', compact('account')) }}">
                @csrf
                <div class="card-header">
                    Registrar movimiento
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label for="amount">
                            Monto <span class="text-danger font-weight-bold">*</span>
                        </label>
                        <input class="form-control" id="amount" type="number" name="amount" oninput="inputMoney(this);">
                    </div>
                    <div class="form-group">
                        <label for="description">Descripción</label>
                        <input class="form-control" id="description" type="text" name="description">
                    </div>
                </div>
                <div class="card-footer">
                    <button class="btn btn-sm btn-primary" type="submit">Registrar</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@push('layout_before_end_body')
<script>
    let inputMoneyTimer;
    function inputMoney(ele) {
        clearTimeout(inputMoneyTimer);
        inputMoneyTimer = setTimeout(function() {
            ele.value = parseFloat(ele.value).toFixed(2).toString();
        }, 800);
    }
</script>
@endpush
