"""Command-line entry points. Every command has --json; run commands need --run-id."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from vulnassess import (
    __version__,
    diff,
    evaluate,
    explain,
    intel,
    pipeline,
    role_model,
    runner,
    visual_simulation,
)
from vulnassess.errors import ConfigError, VulnAssessError
from vulnassess.settings import Settings
from vulnassess.store import Store

DEFAULT_DB = "data/vulnassess.db"
DEFAULT_CONFIG = "config"


def _emit(payload: Any, text: str, as_json: bool) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2) if as_json else text)


def _parse_target(spec: str) -> tuple[str, str, str | None]:
    """IP:nmap[:zap], tolerating Windows drive letters inside the paths."""
    raw = spec.split(":")
    parts: list[str] = []
    index = 0
    while index < len(raw):
        token = raw[index]
        if len(token) == 1 and token.isalpha() and index + 1 < len(raw):
            parts.append(f"{token}:{raw[index + 1]}")
            index += 2
            continue
        parts.append(token)
        index += 1
    if len(parts) < 2:
        raise ConfigError(f"--target {spec!r} must look like IP:nmap.xml[:zap.json]")
    return parts[0], parts[1], parts[2] if len(parts) > 2 else None


def _settings(args: argparse.Namespace) -> Settings:
    return Settings(Path(args.config))


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db)


def cmd_import(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        summary = pipeline.do_import(
            settings, store, args.run_id, args.target_ip, args.nmap, args.zap, args.nikto
        )
    counts = ", ".join(f"{tool} {count}" for tool, count in sorted(summary["findings"].items()))
    _emit(
        summary,
        f"run {summary['run_id']}: {summary['hosts']} host(s); new findings: {counts or 'none'}",
        args.json,
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings(args)
    tools = args.tool or sorted(runner.BUILDERS)
    summary = runner.run_scan(settings, args.target_ip, tools, args.out_dir, execute=args.execute)
    lines = list(summary["commands"])
    if summary["missing"]:
        lines.append(f"MISSING binaries: {', '.join(summary['missing'])} - a human must install them")
    if not summary["executed"]:
        lines.append("Planned only. Pass --execute to run these yourself.")
    _emit(summary, "\n".join(lines), args.json)
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    client = None if args.no_model else explain.OllamaClient(args.ollama_host, args.model)
    with _store(args) as store:
        counts = explain.explain_run(args.run_id, store, client)
    _emit(
        counts,
        f"{counts['llm']} sentence(s) from the model, {counts['template']} deterministic",
        args.json,
    )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    with _store(args) as store:
        result = diff.diff_runs(store, args.before, args.after)
    _emit(result, diff.markdown_table(result), args.json)
    return 0


def _reject_synthetic_labels(
    examples: Sequence[role_model.LabelledHost], allowed: bool
) -> None:
    synthetic = sum(example.label_source == "synthetic" for example in examples)
    if synthetic and not allowed:
        raise ConfigError(
            f"dataset contains {synthetic} synthetic label(s); training on them requires "
            "--allow-synthetic and cannot establish model validity"
        )


def _training_options(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "l2": args.l2,
        "min_feature_count": args.min_feature_count,
    }


def cmd_model_labels(args: argparse.Namespace) -> int:
    with _store(args) as store:
        hosts = store.hosts(args.run_id)
    if not hosts:
        raise ConfigError(f"MISSING: hosts for run {args.run_id!r}")
    path = role_model.export_label_template(hosts, args.run_id, args.out)
    payload = {"run_id": args.run_id, "hosts": len(hosts), "path": str(path)}
    _emit(payload, f"wrote {len(hosts)} unlabeled host(s) to {path}", args.json)
    return 0


def cmd_model_train(args: argparse.Namespace) -> int:
    examples = role_model.load_examples(args.data)
    _reject_synthetic_labels(examples, args.allow_synthetic)
    model = role_model.train(examples, **_training_options(args))
    validation_metrics = None
    if args.validation:
        validation = role_model.load_examples(args.validation)
        _reject_synthetic_labels(validation, args.allow_synthetic)
        overlap = sorted({item.group for item in examples} & {item.group for item in validation})
        if overlap:
            raise ConfigError(
                f"training/validation group leakage: {overlap[:5]}; use independent hosts"
            )
        model = role_model.calibrate(model, validation)
        validation_metrics = role_model.evaluate(model, validation)
    path = role_model.save_model(model, args.out)
    payload = {
        "path": str(path),
        "model_hash": model.model_hash,
        "classes": list(model.classes),
        "features": len(model.features),
        "training": model.training,
        "validation": validation_metrics,
    }
    text = (
        f"model {model.model_hash}: {len(model.classes)} classes, "
        f"{len(model.features)} features; written to {path}"
    )
    if validation_metrics:
        text += (
            f"; validation accuracy={validation_metrics['accuracy']:.3f} "
            f"coverage={validation_metrics['coverage']:.3f} "
            f"macro_f1={validation_metrics['macro_f1']:.3f}"
        )
    else:
        text += "; NOT VALIDATED (no independent --validation dataset)"
    _emit(payload, text, args.json)
    return 0


def cmd_model_cross_validate(args: argparse.Namespace) -> int:
    examples = role_model.load_examples(args.data)
    _reject_synthetic_labels(examples, args.allow_synthetic)
    result = role_model.cross_validate(
        examples, folds=args.folds, **_training_options(args)
    )
    aggregate = result["aggregate"]
    text = (
        f"{result['folds']}-fold grouped CV: accuracy={aggregate['accuracy']:.3f} "
        f"coverage={aggregate['coverage']:.3f} macro_f1={aggregate['macro_f1']:.3f} "
        f"log_loss={aggregate['log_loss']:.3f}"
    )
    _emit(result, text, args.json)
    return 0


def cmd_model_evaluate(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    examples = role_model.load_examples(args.data)
    result = role_model.evaluate(model, examples)
    text = (
        f"model {model.model_hash}: accuracy={result['accuracy']:.3f} "
        f"coverage={result['coverage']:.3f} selective_accuracy="
        f"{result['selective_accuracy']} macro_f1={result['macro_f1']:.3f} "
        f"ECE={result['expected_calibration_error']:.3f}"
    )
    _emit(result, text, args.json)
    return 0


def cmd_model_predict(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    with _store(args) as store:
        hosts = store.hosts(args.run_id)
    if not hosts:
        raise ConfigError(f"MISSING: hosts for run {args.run_id!r}")
    predictions = [
        {"host_ip": host.ip, **model.predict(host).to_json()} for host in hosts
    ]
    lines = [
        f"{item['host_ip']}: {item['label']} confidence={item['confidence']:.3f} "
        f"margin={item['margin']:.3f}{' ABSTAINED' if item['abstained'] else ''}; "
        f"evidence: {item['evidence']}"
        for item in predictions
    ]
    lines.append("SHADOW ONLY: predictions were not written to context and cannot change ranks")
    _emit(predictions, "\n".join(lines), args.json)
    return 0


def cmd_model_inspect(args: argparse.Namespace) -> int:
    model = role_model.load_model(args.model_artifact)
    top: dict[str, list[dict[str, Any]]] = {}
    for class_index, label in enumerate(model.classes):
        weighted = sorted(
            zip(model.features, model.coefficients[class_index], strict=True),
            key=lambda item: (-item[1], item[0]),
        )[: args.top]
        top[label] = [
            {"feature": feature, "weight": round(weight, 6)}
            for feature, weight in weighted
        ]
    payload = {**model.to_json(), "top_positive_features": top}
    lines = [
        f"model {model.model_hash} task={model.task} classes={len(model.classes)} "
        f"features={len(model.features)} temperature={model.temperature}"
    ]
    for label in model.classes:
        summary = ", ".join(
            f"{item['feature']}={item['weight']:+.3f}" for item in top[label]
        )
        lines.append(f"  {label}: {summary}")
    _emit(payload, "\n".join(lines), args.json)
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    settings = _settings(args)
    model = role_model.load_model(args.model_artifact)
    report_path = Path(args.model_report)
    if not report_path.is_file():
        raise ConfigError(f"MISSING: model evaluation report {report_path}")
    try:
        model_report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError(f"invalid model evaluation report {report_path}: {error}") from error
    with _store(args) as store:
        if store.run_info(args.run_id) is None:
            raise ConfigError(f"MISSING: run {args.run_id!r} in the store")
        payload = visual_simulation.build_payload(
            store, args.run_id, model, model_report, settings.weights
        )
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(visual_simulation.render(payload), encoding="utf-8")
    result = {
        "run_id": args.run_id,
        "model_hash": model.model_hash,
        "hosts": len(payload["hosts"]),
        "findings": len(payload["ranked"]),
        "output": str(output),
    }
    _emit(
        result,
        f"visual replay for {args.run_id}: {result['hosts']} hosts, "
        f"{result['findings']} findings -> {output}",
        args.json,
    )
    return 0


def cmd_intel_load(args: argparse.Namespace) -> int:
    with _store(args) as store:
        counts = intel.load_feeds(args.from_dir, store)
    _emit(
        counts,
        "loaded " + ", ".join(f"{feed} {count}" for feed, count in sorted(counts.items())),
        args.json,
    )
    return 0


def cmd_intel_status(args: argparse.Namespace) -> int:
    with _store(args) as store:
        meta = store.feeds_meta()
    if not meta:
        _emit(
            {},
            "no feed snapshots loaded; run: vulnassess intel load --from-dir <dir>",
            args.json,
        )
        return 0
    lines = [
        f"{feed:5} date {info['file_date'] or '-':10} rows {info['rows']:>7} "
        f"sha256 {info['sha256'][:16]}"
        for feed, info in sorted(meta.items())
    ]
    _emit(meta, "\n".join(lines), args.json)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    with _store(args) as store:
        counts = intel.enrich_run(args.run_id, store)
    _emit(
        counts,
        f"{counts['matched']}/{counts['findings']} findings matched; "
        f"{counts['enrichments']} enrichment(s)",
        args.json,
    )
    return 0


def cmd_context(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        profiles = pipeline.do_context(settings, store, args.run_id)
    lines = []
    for profile in profiles:
        controls = ", ".join(
            f"{key}={value.value}" for key, value in sorted(profile.controls.items())
        )
        lines.append(
            f"{profile.host_ip}: role={profile.role.value} ({profile.role.confidence:.2f}) "
            f"exposure={profile.exposure.value} ({profile.exposure.confidence:.2f})"
        )
        lines.append(f"    evidence: {profile.role.evidence}")
        lines.append(f"    controls: {controls}")
    _emit([profile.to_json() for profile in profiles], "\n".join(lines), args.json)
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        scores = pipeline.do_rank(settings, store, args.run_id)
    limit = args.top if getattr(args, "top", None) else len(scores)
    lines = []
    for position, item in enumerate(scores[:limit], start=1):
        lines.append(
            f"{position:>3} {item.risk:>6} {item.band:<8} {item.host_ip:<15} "
            f"{(item.cve_id or '-'):<16} base {str(item.base_score or '-'):<5} "
            f"env {str(item.env_score or '-'):<5} {item.reason}"
        )
    _emit([item.to_json() for item in scores], "\n".join(lines), args.json)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings = _settings(args)
    with _store(args) as store:
        path = pipeline.do_report(settings, store, args.run_id, args.out)
    _emit({"report": str(path)}, f"report written to {path}", args.json)
    return 0


def _live_ranking() -> list[Any]:
    print("Paste one rank per line (space-separated ids share a rank). Blank line ends input.")
    order: list[Any] = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            break
        ids = line.split()
        order.append(ids if len(ids) > 1 else ids[0])
    return order


def cmd_eval(args: argparse.Namespace) -> int:
    with _store(args) as store:
        if args.live:
            truth = {
                "experts": [{"name": "live", "ranking": _live_ranking()}],
                "expert_critical": [],
            }
            result = evaluate.evaluate(pipeline.baseline_orders(store, args.run_id), truth)
        else:
            if not args.truth:
                raise ConfigError("eval needs --truth <path> or --live")
            result = pipeline.do_eval(store, args.run_id, args.truth)
    _emit(result, evaluate.markdown_table(result), args.json)
    return 0


def cmd_two_machine(args: argparse.Namespace) -> int:
    with _store(args) as store:
        text = pipeline.two_machine_table(store, args.run_id, args.cve)
    _emit({"two_machine": text}, text, args.json)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    settings = _settings(args)
    run_id = args.run_id
    with _store(args) as store:
        for spec in args.target:
            target_ip, nmap_path, zap_path = _parse_target(spec)
            summary = pipeline.do_import(
                settings, store, run_id, target_ip, nmap_path, zap_path
            )
            counts = ", ".join(
                f"{tool} {count}" for tool, count in sorted(summary["findings"].items())
            )
            print(f"import {target_ip}: {summary['hosts']} host(s); new findings: {counts}")

        loaded = intel.load_feeds(args.feeds, store)
        print("intel: " + ", ".join(f"{feed} {count}" for feed, count in sorted(loaded.items())))
        matched = intel.enrich_run(run_id, store)
        print(f"enrich: {matched['matched']}/{matched['findings']} findings matched")

        profiles = pipeline.do_context(settings, store, run_id)
        for profile in profiles:
            print(
                f"context {profile.host_ip}: role={profile.role.value} "
                f"({profile.role.confidence:.2f}) exposure={profile.exposure.value}"
            )

        scores = pipeline.do_rank(settings, store, run_id)
        print("\nTop findings")
        for position, item in enumerate(scores[:10], start=1):
            print(f"{position:>3} {item.risk:>6} {item.band:<8} {item.host_ip:<15} {item.reason}")

        path = pipeline.do_report(settings, store, run_id, args.out)
        print(f"\nreport: {path}")

        if args.truth:
            result = pipeline.do_eval(store, run_id, args.truth)
            print("\n" + evaluate.markdown_table(result))

        print("\ntwo-machine comparison")
        print(pipeline.two_machine_table(store, run_id))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnassess",
        description="Local-first vulnerability prioritisation for authorised lab targets only.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="configuration directory")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite store path")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler, run_id: bool = True, **kwargs) -> argparse.ArgumentParser:
        sub = subparsers.add_parser(name, **kwargs)
        sub.add_argument("--json", action="store_true", help="emit JSON")
        if run_id:
            sub.add_argument("--run-id", required=True, help="run identifier")
        sub.set_defaults(handler=handler)
        return sub

    importer = add("import", cmd_import, help="import existing scanner output for one target")
    importer.add_argument("--target-ip", required=True)
    importer.add_argument("--nmap", required=True)
    importer.add_argument("--zap")
    importer.add_argument("--nikto")

    scanner = add(
        "scan", cmd_scan, run_id=False, help="plan the scanner commands for one authorised target"
    )
    scanner.add_argument("--target-ip", required=True)
    scanner.add_argument(
        "--tool", action="append", default=None, choices=sorted(runner.BUILDERS)
    )
    scanner.add_argument("--out-dir", default="data/captures")
    scanner.add_argument(
        "--execute", action="store_true", help="actually run them (a human decision)"
    )

    intel_parser = subparsers.add_parser("intel", help="offline feed snapshots")
    intel_sub = intel_parser.add_subparsers(dest="intel_command", required=True)
    load = intel_sub.add_parser("load", help="load NVD/EPSS/KEV snapshots from a directory")
    load.add_argument("--json", action="store_true")
    load.add_argument("--from-dir", required=True, dest="from_dir")
    load.set_defaults(handler=cmd_intel_load)
    status = intel_sub.add_parser("status", help="show the loaded snapshots")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=cmd_intel_status)

    add("enrich", cmd_enrich, help="attach CVE intelligence to findings")
    add("context", cmd_context, help="infer role, exposure and controls per host")
    rank = add("rank", cmd_rank, help="rank findings with the documented formula")
    rank.add_argument("--top", type=int)
    reporter = add("report", cmd_report, help="write the offline HTML report")
    reporter.add_argument("--out", required=True)
    evaluator = add("eval", cmd_eval, help="compare our ranking with expert rankings")
    evaluator.add_argument("--truth")
    evaluator.add_argument("--live", action="store_true")
    two = add("two-machine", cmd_two_machine, help="one CVE, two machines, two answers")
    two.add_argument("--cve")

    explainer = add("explain", cmd_explain, help="write a plain-English sentence per finding")
    explainer.add_argument("--model", default=explain.DEFAULT_MODEL)
    explainer.add_argument("--ollama-host", default=explain.DEFAULT_HOST)
    explainer.add_argument(
        "--no-model", action="store_true", help="use the deterministic sentence only"
    )

    differ = subparsers.add_parser("diff", help="compare two runs by finding fingerprint")
    differ.add_argument("--json", action="store_true")
    differ.add_argument("--before", required=True)
    differ.add_argument("--after", required=True)
    differ.set_defaults(handler=cmd_diff)

    model_parser = subparsers.add_parser(
        "model", help="train and evaluate the shadow asset-role classifier"
    )
    model_sub = model_parser.add_subparsers(dest="model_command", required=True)

    labels = model_sub.add_parser("labels", help="export unlabeled hosts for human review")
    labels.add_argument("--json", action="store_true")
    labels.add_argument("--run-id", required=True)
    labels.add_argument("--out", required=True)
    labels.set_defaults(handler=cmd_model_labels)

    def add_training_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--epochs", type=int, default=600)
        command.add_argument("--learning-rate", type=float, default=0.2)
        command.add_argument("--l2", type=float, default=0.001)
        command.add_argument("--min-feature-count", type=int, default=1)
        command.add_argument("--allow-synthetic", action="store_true")

    trainer = model_sub.add_parser("train", help="fit and save a role-model artifact")
    trainer.add_argument("--json", action="store_true")
    trainer.add_argument("--data", required=True)
    trainer.add_argument("--validation")
    trainer.add_argument("--out", required=True)
    add_training_options(trainer)
    trainer.set_defaults(handler=cmd_model_train)

    cross_validator = model_sub.add_parser(
        "cross-validate", help="grouped deterministic cross-validation"
    )
    cross_validator.add_argument("--json", action="store_true")
    cross_validator.add_argument("--data", required=True)
    cross_validator.add_argument("--folds", type=int, default=5)
    add_training_options(cross_validator)
    cross_validator.set_defaults(handler=cmd_model_cross_validate)

    model_evaluator = model_sub.add_parser(
        "evaluate", help="evaluate a frozen artifact on independent labels"
    )
    model_evaluator.add_argument("--json", action="store_true")
    model_evaluator.add_argument("--model", dest="model_artifact", required=True)
    model_evaluator.add_argument("--data", required=True)
    model_evaluator.set_defaults(handler=cmd_model_evaluate)

    predictor = model_sub.add_parser(
        "predict", help="predict run roles in shadow mode without changing ranks"
    )
    predictor.add_argument("--json", action="store_true")
    predictor.add_argument("--run-id", required=True)
    predictor.add_argument("--model", dest="model_artifact", required=True)
    predictor.set_defaults(handler=cmd_model_predict)

    inspector = model_sub.add_parser("inspect", help="inspect artifact metadata and weights")
    inspector.add_argument("--json", action="store_true")
    inspector.add_argument("--model", dest="model_artifact", required=True)
    inspector.add_argument("--top", type=int, default=8)
    inspector.set_defaults(handler=cmd_model_inspect)

    visualizer = add(
        "visualize", cmd_visualize, help="render an interactive visual replay of an existing run"
    )
    visualizer.add_argument("--model", dest="model_artifact", required=True)
    visualizer.add_argument("--model-report", required=True)
    visualizer.add_argument("--out", required=True)

    demo = subparsers.add_parser("demo", help="run the whole pipeline on supplied files")
    demo.add_argument("--json", action="store_true")
    demo.add_argument("--run-id", default="demo")
    demo.add_argument("--target", action="append", required=True, help="IP:nmap.xml[:zap.json]")
    demo.add_argument("--feeds", required=True)
    demo.add_argument("--out", required=True)
    demo.add_argument("--truth")
    demo.set_defaults(handler=cmd_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except VulnAssessError as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return error.exit_code
